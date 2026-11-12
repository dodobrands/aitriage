package handlers

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/dodobrands/aitriage/internal/models"
	"github.com/dodobrands/aitriage/internal/server/middleware"
	"github.com/dodobrands/aitriage/internal/server/repositories"
	"github.com/dodobrands/aitriage/internal/server/utils"
)

type ProductHandler struct {
	repo *repositories.ProductRepository
}

func NewProductHandler(repo *repositories.ProductRepository) *ProductHandler {
	return &ProductHandler{repo: repo}
}

// --- Product Types ---

func (h *ProductHandler) HandleListProductTypes(w http.ResponseWriter, r *http.Request) {
	pts, err := h.repo.ListProductTypes(r.Context())
	if err != nil {
		utils.JSONError(w, "Failed to list product types", http.StatusInternalServerError)
		return
	}
	_ = json.NewEncoder(w).Encode(pts)
}

// --- Products ---

func (h *ProductHandler) HandleListProducts(w http.ResponseWriter, r *http.Request) {
	claims, err := middleware.ExtractClaims(r)
	if err != nil {
		utils.JSONError(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	products, err := h.repo.List(r.Context(), claims.UserID, claims.GlobalRole)
	if err != nil {
		utils.JSONError(w, "Failed to list products", http.StatusInternalServerError)
		return
	}
	_ = json.NewEncoder(w).Encode(products)
}

func (h *ProductHandler) HandleCreateProduct(w http.ResponseWriter, r *http.Request) {
	claims, err := middleware.ExtractClaims(r)
	if err != nil {
		utils.JSONError(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	var req models.Product
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		utils.JSONError(w, "Invalid data", http.StatusBadRequest)
		return
	}

	req.CreatedBy = &claims.UserID

	id, err := h.repo.Create(r.Context(), &req)
	if err != nil {
		utils.JSONError(w, "Failed to create product", http.StatusInternalServerError)
		return
	}

	// Make the creator an owner of the product
	_ = h.repo.AddMember(r.Context(), id, claims.UserID, "owner")

	_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "id": id})
}

func (h *ProductHandler) HandleUpdateProduct(w http.ResponseWriter, r *http.Request) {
	idStr := r.URL.Query().Get("id")
	id, _ := strconv.ParseInt(idStr, 10, 64)

	var req models.Product
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		utils.JSONError(w, "Invalid data", http.StatusBadRequest)
		return
	}
	req.ID = id

	err := h.repo.Update(r.Context(), &req)
	if err != nil {
		utils.JSONError(w, "Failed to update product", http.StatusInternalServerError)
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"ok": true})
}

func (h *ProductHandler) HandleDeleteProduct(w http.ResponseWriter, r *http.Request) {
	idStr := r.URL.Query().Get("id")
	id, _ := strconv.ParseInt(idStr, 10, 64)

	err := h.repo.Delete(r.Context(), id)
	if err != nil {
		utils.JSONError(w, "Failed to delete product", http.StatusInternalServerError)
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"ok": true})
}

func (h *ProductHandler) HandleAddProductMember(w http.ResponseWriter, r *http.Request) {
	productIDStr := r.URL.Query().Get("id")
	productID, _ := strconv.ParseInt(productIDStr, 10, 64)

	var req struct {
		UserID int64  `json:"user_id"`
		Role   string `json:"role"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		utils.JSONError(w, "Invalid data", http.StatusBadRequest)
		return
	}

	err := h.repo.AddMember(r.Context(), productID, req.UserID, req.Role)
	if err != nil {
		utils.JSONError(w, "Failed to add member", http.StatusInternalServerError)
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"ok": true})
}
