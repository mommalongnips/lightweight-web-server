package main

import (
	"archive/zip"
	"crypto/rand"
	"crypto/subtle"
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

//go:embed index.html
var indexHTML embed.FS

var (
	dataDir        string
	masterPassword string
	maxUploadSize  int64

	sessions   = map[string]time.Time{}
	sessionsMu sync.RWMutex
)

func main() {
	dataDir = env("DATA_DIR", "/data")
	masterPassword = os.Getenv("MASTER_PASSWORD")
	port := env("PORT", "8080")

	maxUpload := env("MAX_UPLOAD_SIZE", "10737418240") // 10GB
	parsed, err := strconv.ParseInt(maxUpload, 10, 64)
	if err != nil {
		log.Fatalf("invalid MAX_UPLOAD_SIZE: %v", err)
	}
	maxUploadSize = parsed

	// Ensure data dir exists
	if err := os.MkdirAll(dataDir, 0755); err != nil {
		log.Fatalf("cannot create data dir: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", handleIndex)
	mux.HandleFunc("/api/auth/check", handleAuthCheck)
	mux.HandleFunc("/api/auth/login", handleLogin)
	mux.HandleFunc("/api/files", requireAuth(handleFiles))
	mux.HandleFunc("/api/download", requireAuth(handleDownload))
	mux.HandleFunc("/api/download-zip", requireAuth(handleDownloadZip))
	mux.HandleFunc("/api/upload", requireAuth(handleUpload))
	mux.HandleFunc("/api/mkdir", requireAuth(handleMkdir))
	mux.HandleFunc("/api/delete", requireAuth(handleDelete))

	log.Printf("file-site listening on :%s (data: %s, auth: %v)", port, dataDir, masterPassword != "")
	if err := http.ListenAndServe(":"+port, mux); err != nil {
		log.Fatal(err)
	}
}

func env(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// --- Auth ---

func requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if masterPassword == "" {
			next(w, r)
			return
		}
		cookie, err := r.Cookie("session")
		if err != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		sessionsMu.RLock()
		exp, ok := sessions[cookie.Value]
		sessionsMu.RUnlock()
		if !ok || time.Now().After(exp) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

func handleAuthCheck(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	result := map[string]interface{}{"required": masterPassword != ""}
	if masterPassword != "" {
		cookie, err := r.Cookie("session")
		if err == nil {
			sessionsMu.RLock()
			exp, ok := sessions[cookie.Value]
			sessionsMu.RUnlock()
			result["authenticated"] = ok && time.Now().Before(exp)
		} else {
			result["authenticated"] = false
		}
	} else {
		result["authenticated"] = true
	}
	writeJSON(w, result)
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if masterPassword == "" {
		writeJSON(w, map[string]interface{}{"ok": true})
		return
	}
	var body struct {
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if subtle.ConstantTimeCompare([]byte(body.Password), []byte(masterPassword)) != 1 {
		time.Sleep(500 * time.Millisecond) // brute-force mitigation
		http.Error(w, "wrong password", http.StatusForbidden)
		return
	}

	token := make([]byte, 32)
	rand.Read(token)
	sessionID := hex.EncodeToString(token)

	sessionsMu.Lock()
	sessions[sessionID] = time.Now().Add(24 * time.Hour)
	sessionsMu.Unlock()

	http.SetCookie(w, &http.Cookie{
		Name:     "session",
		Value:    sessionID,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   86400,
	})
	writeJSON(w, map[string]interface{}{"ok": true})
}

// --- Path safety ---

func safePath(reqPath string) (string, error) {
	cleaned := filepath.Clean(reqPath)
	// Prevent directory traversal
	if strings.Contains(cleaned, "..") {
		return "", fmt.Errorf("invalid path")
	}
	full := filepath.Join(dataDir, cleaned)
	// Resolve symlinks and verify the path is within dataDir
	absData, err := filepath.Abs(dataDir)
	if err != nil {
		return "", err
	}
	absFull, err := filepath.Abs(full)
	if err != nil {
		return "", err
	}
	if !strings.HasPrefix(absFull, absData) {
		return "", fmt.Errorf("path outside data directory")
	}
	return full, nil
}

// --- API handlers ---

type fileEntry struct {
	Name     string    `json:"name"`
	IsDir    bool      `json:"isDir"`
	Size     int64     `json:"size"`
	Modified time.Time `json:"modified"`
}

func handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	data, _ := fs.ReadFile(indexHTML, "index.html")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(data)
}

func handleFiles(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	reqPath := r.URL.Query().Get("path")
	if reqPath == "" {
		reqPath = "/"
	}
	dirPath, err := safePath(reqPath)
	if err != nil {
		http.Error(w, "invalid path", http.StatusBadRequest)
		return
	}
	entries, err := os.ReadDir(dirPath)
	if err != nil {
		http.Error(w, "cannot read directory", http.StatusNotFound)
		return
	}
	files := make([]fileEntry, 0, len(entries))
	for _, e := range entries {
		info, err := e.Info()
		if err != nil {
			continue
		}
		files = append(files, fileEntry{
			Name:     e.Name(),
			IsDir:    e.IsDir(),
			Size:     info.Size(),
			Modified: info.ModTime(),
		})
	}
	writeJSON(w, files)
}

func handleDownload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	reqPath := r.URL.Query().Get("path")
	filePath, err := safePath(reqPath)
	if err != nil {
		http.Error(w, "invalid path", http.StatusBadRequest)
		return
	}
	info, err := os.Stat(filePath)
	if err != nil || info.IsDir() {
		http.Error(w, "file not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, filepath.Base(filePath)))
	http.ServeFile(w, r, filePath)
}

func handleDownloadZip(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	reqPath := r.URL.Query().Get("path")
	dirPath, err := safePath(reqPath)
	if err != nil {
		http.Error(w, "invalid path", http.StatusBadRequest)
		return
	}
	info, err := os.Stat(dirPath)
	if err != nil || !info.IsDir() {
		http.Error(w, "directory not found", http.StatusNotFound)
		return
	}

	folderName := filepath.Base(dirPath)
	if folderName == "." || folderName == "/" {
		folderName = "files"
	}

	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s.zip"`, folderName))

	zw := zip.NewWriter(w)
	defer zw.Close()

	filepath.WalkDir(dirPath, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		relPath, err := filepath.Rel(dirPath, path)
		if err != nil {
			return err
		}
		// Use forward slashes in zip
		relPath = filepath.ToSlash(relPath)

		info, err := d.Info()
		if err != nil {
			return err
		}
		header, err := zip.FileInfoHeader(info)
		if err != nil {
			return err
		}
		header.Name = relPath
		header.Method = zip.Deflate

		writer, err := zw.CreateHeader(header)
		if err != nil {
			return err
		}
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		defer f.Close()
		_, err = io.Copy(writer, f)
		return err
	})
}

func handleUpload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxUploadSize)

	reqPath := r.URL.Query().Get("path")
	if reqPath == "" {
		reqPath = "/"
	}
	dirPath, err := safePath(reqPath)
	if err != nil {
		http.Error(w, "invalid path", http.StatusBadRequest)
		return
	}

	if err := r.ParseMultipartForm(32 << 20); err != nil { // 32MB buffer
		http.Error(w, "upload too large or invalid", http.StatusBadRequest)
		return
	}

	uploaded := []string{}
	for _, fHeaders := range r.MultipartForm.File {
		for _, fh := range fHeaders {
			// Validate filename
			name := filepath.Base(fh.Filename)
			if name == "." || name == ".." {
				continue
			}
			destPath := filepath.Join(dirPath, name)
			// Verify destination is still within data dir
			if _, err := safePath(filepath.Join(reqPath, name)); err != nil {
				continue
			}

			src, err := fh.Open()
			if err != nil {
				continue
			}
			dst, err := os.Create(destPath)
			if err != nil {
				src.Close()
				continue
			}
			io.Copy(dst, src)
			dst.Close()
			src.Close()
			uploaded = append(uploaded, name)
		}
	}
	writeJSON(w, map[string]interface{}{"uploaded": uploaded})
}

func handleMkdir(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var body struct {
		Path string `json:"path"`
		Name string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if body.Path == "" {
		body.Path = "/"
	}
	// Validate the folder name
	name := filepath.Base(body.Name)
	if name == "." || name == ".." || name == "" {
		http.Error(w, "invalid folder name", http.StatusBadRequest)
		return
	}
	fullPath, err := safePath(filepath.Join(body.Path, name))
	if err != nil {
		http.Error(w, "invalid path", http.StatusBadRequest)
		return
	}
	if err := os.Mkdir(fullPath, 0755); err != nil {
		if os.IsExist(err) {
			http.Error(w, "folder already exists", http.StatusConflict)
		} else {
			http.Error(w, "cannot create folder", http.StatusInternalServerError)
		}
		return
	}
	writeJSON(w, map[string]interface{}{"ok": true})
}

func handleDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	reqPath := r.URL.Query().Get("path")
	targetPath, err := safePath(reqPath)
	if err != nil {
		http.Error(w, "invalid path", http.StatusBadRequest)
		return
	}
	// Don't allow deleting the root data directory
	absData, _ := filepath.Abs(dataDir)
	absTarget, _ := filepath.Abs(targetPath)
	if absTarget == absData {
		http.Error(w, "cannot delete root", http.StatusForbidden)
		return
	}
	if err := os.RemoveAll(targetPath); err != nil {
		http.Error(w, "cannot delete", http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]interface{}{"ok": true})
}

// --- Helpers ---

func writeJSON(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}
