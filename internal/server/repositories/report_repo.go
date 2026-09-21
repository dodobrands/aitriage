package repositories

import (
	"database/sql"
	"time"
)

type Report struct {
	ID          int       `json:"id"`
	Timestamp   time.Time `json:"timestamp"`
	TargetScope string    `json:"target_scope"`
	Format      string    `json:"format"`
	Status      string    `json:"status"`
	DownloadURL string    `json:"download_url"`
	ProductID   *int64    `json:"product_id"`
}

type ReportRepository struct {
	db *sql.DB
}

func NewReportRepository(db *sql.DB) *ReportRepository {
	return &ReportRepository{db: db}
}

func (r *ReportRepository) ListReports() ([]Report, error) {
	rows, err := r.db.Query(`
		SELECT id, timestamp, target_scope, format, status, COALESCE(download_url, ''), product_id
		FROM reports
		ORDER BY timestamp DESC
	`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var reports []Report
	for rows.Next() {
		var rep Report
		if err := rows.Scan(&rep.ID, &rep.Timestamp, &rep.TargetScope, &rep.Format, &rep.Status, &rep.DownloadURL, &rep.ProductID); err != nil {
			return nil, err
		}
		reports = append(reports, rep)
	}
	return reports, nil
}

// GetReport returns one report row by id.
func (r *ReportRepository) GetReport(id int64) (*Report, error) {
	row := r.db.QueryRow(`
		SELECT id, timestamp, target_scope, format, status, COALESCE(download_url, ''), product_id
		FROM reports WHERE id = ?
	`, id)
	var rep Report
	if err := row.Scan(&rep.ID, &rep.Timestamp, &rep.TargetScope, &rep.Format, &rep.Status, &rep.DownloadURL, &rep.ProductID); err != nil {
		return nil, err
	}
	return &rep, nil
}

// CreateReport records a generated report and returns its id so the caller can
// hand back a download link that resolves to exactly this row.
func (r *ReportRepository) CreateReport(scope, format, status string, productID *int64, downloadURL string) (int64, error) {
	res, err := r.db.Exec(`
		INSERT INTO reports (target_scope, format, status, product_id, download_url)
		VALUES (?, ?, ?, ?, ?)
	`, scope, format, status, productID, downloadURL)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// SetDownloadURL attaches the resolved download link to an existing report.
func (r *ReportRepository) SetDownloadURL(id int64, url string) error {
	_, err := r.db.Exec(`UPDATE reports SET download_url = ? WHERE id = ?`, url, id)
	return err
}
