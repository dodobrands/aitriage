package repositories

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/dodobrands/aitriage/internal/models"
)

type ProductRepository struct {
	db *sql.DB
}

func NewProductRepository(db *sql.DB) *ProductRepository {
	return &ProductRepository{db: db}
}

func (r *ProductRepository) Create(ctx context.Context, p *models.Product) (int64, error) {
	res, err := r.db.ExecContext(ctx, `
		INSERT INTO products (product_type_id, name, description, repo_url, lifecycle, origin, business_criticality, platform, tech_stack, sla_critical, sla_high, sla_medium, sla_low, created_by)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, p.ProductTypeID, p.Name, p.Description, p.RepoURL, p.Lifecycle, p.Origin, p.BusinessCriticality, p.Platform, p.TechStack, p.SLACritical, p.SLAHigh, p.SLAMedium, p.SLALow, p.CreatedBy)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func (r *ProductRepository) GetByID(ctx context.Context, id int64) (*models.Product, error) {
	row := r.db.QueryRowContext(ctx, `
		SELECT id, product_type_id, name, description, repo_url, lifecycle, origin, business_criticality, platform, tech_stack, sla_critical, sla_high, sla_medium, sla_low, created_by, created_at, updated_at
		FROM products WHERE id = ?
	`, id)

	var p models.Product
	err := row.Scan(&p.ID, &p.ProductTypeID, &p.Name, &p.Description, &p.RepoURL, &p.Lifecycle, &p.Origin, &p.BusinessCriticality, &p.Platform, &p.TechStack, &p.SLACritical, &p.SLAHigh, &p.SLAMedium, &p.SLALow, &p.CreatedBy, &p.CreatedAt, &p.UpdatedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("product not found")
		}
		return nil, err
	}
	return &p, nil
}

func (r *ProductRepository) List(ctx context.Context, userID int64, globalRole string) ([]models.Product, error) {
	var rows *sql.Rows
	var err error

	if globalRole == "superadmin" || globalRole == "admin" {
		rows, err = r.db.QueryContext(ctx, `
			SELECT id, product_type_id, name, description, repo_url, lifecycle, origin, business_criticality, platform, tech_stack, sla_critical, sla_high, sla_medium, sla_low, created_by, created_at, updated_at
			FROM products
		`)
	} else {
		rows, err = r.db.QueryContext(ctx, `
			SELECT p.id, p.product_type_id, p.name, p.description, p.repo_url, p.lifecycle, p.origin, p.business_criticality, p.platform, p.tech_stack, p.sla_critical, p.sla_high, p.sla_medium, p.sla_low, p.created_by, p.created_at, p.updated_at
			FROM products p
			INNER JOIN product_members pm ON p.id = pm.product_id
			WHERE pm.user_id = ?
		`, userID)
	}

	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var products []models.Product
	for rows.Next() {
		var p models.Product
		if err := rows.Scan(&p.ID, &p.ProductTypeID, &p.Name, &p.Description, &p.RepoURL, &p.Lifecycle, &p.Origin, &p.BusinessCriticality, &p.Platform, &p.TechStack, &p.SLACritical, &p.SLAHigh, &p.SLAMedium, &p.SLALow, &p.CreatedBy, &p.CreatedAt, &p.UpdatedAt); err != nil {
			return nil, err
		}
		products = append(products, p)
	}
	return products, nil
}

func (r *ProductRepository) Update(ctx context.Context, p *models.Product) error {
	_, err := r.db.ExecContext(ctx, `
		UPDATE products 
		SET product_type_id = ?, name = ?, description = ?, repo_url = ?, lifecycle = ?, origin = ?, business_criticality = ?, platform = ?, tech_stack = ?, sla_critical = ?, sla_high = ?, sla_medium = ?, sla_low = ?, updated_at = CURRENT_TIMESTAMP
		WHERE id = ?
	`, p.ProductTypeID, p.Name, p.Description, p.RepoURL, p.Lifecycle, p.Origin, p.BusinessCriticality, p.Platform, p.TechStack, p.SLACritical, p.SLAHigh, p.SLAMedium, p.SLALow, p.ID)
	return err
}

func (r *ProductRepository) Delete(ctx context.Context, id int64) error {
	_, err := r.db.ExecContext(ctx, `DELETE FROM products WHERE id = ?`, id)
	return err
}

func (r *ProductRepository) AddMember(ctx context.Context, productID, userID int64, role string) error {
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO product_members (product_id, user_id, role)
		VALUES (?, ?, ?)
		ON CONFLICT(product_id, user_id) DO UPDATE SET role = excluded.role
	`, productID, userID, role)
	return err
}

func (r *ProductRepository) ListProductTypes(ctx context.Context) ([]models.ProductType, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT id, name, description, created_at FROM product_types`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var pts []models.ProductType
	for rows.Next() {
		var pt models.ProductType
		if err := rows.Scan(&pt.ID, &pt.Name, &pt.Description, &pt.CreatedAt); err != nil {
			return nil, err
		}
		pts = append(pts, pt)
	}
	return pts, nil
}

// FindOrCreateByPath looks up a product by name (derived from scan path).
// If not found, it auto-creates one and returns its ID.
func (r *ProductRepository) FindOrCreateByPath(ctx context.Context, scanPath string) (int64, error) {
	// Clean the path
	path := scanPath
	// Strip trailing slashes
	for len(path) > 1 && (path[len(path)-1] == '/' || path[len(path)-1] == '\\') {
		path = path[:len(path)-1]
	}
	// Strip Docker mount prefixes to get the real project name
	// /host/aitriage → aitriage
	// /host/Documents/GitHub/myapp → myapp
	// /project → use basename
	for _, prefix := range []string{"/host/", "/project/"} {
		if len(path) > len(prefix) && path[:len(prefix)] == prefix {
			path = path[len(prefix):]
		}
	}
	// Use the last path component as a readable name
	name := path
	for i := len(name) - 1; i >= 0; i-- {
		if name[i] == '/' || name[i] == '\\' {
			name = name[i+1:]
			break
		}
	}
	if name == "" || name == "." || name == "project" || name == "host" {
		name = "unnamed-project"
	}

	// Try to find existing by scan path first (exact match), then by name
	var id int64
	err := r.db.QueryRowContext(ctx, `SELECT id FROM products WHERE repo_url = ?`, scanPath).Scan(&id)
	if err == nil {
		return id, nil
	}

	// Create new product with scan path stored as repo_url for uniqueness
	res, err := r.db.ExecContext(ctx, `
		INSERT INTO products (name, description, repo_url, lifecycle, origin, business_criticality, sla_critical, sla_high, sla_medium, sla_low)
		VALUES (?, ?, ?, 'production', 'internal', 'high', 1, 7, 30, 90)
	`, name, fmt.Sprintf("Auto-created from scan of %s", scanPath), scanPath)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}
