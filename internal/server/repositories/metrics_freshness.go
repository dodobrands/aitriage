package repositories

import (
	"context"
	"database/sql"
	"time"
)

// Normalize timestamps before taking MAX: stored SQLite and RFC3339 dates may
// have different separators and offsets. Failed attempts do not refresh results.
func (r *MetricsRepository) populateFreshness(ctx context.Context, metrics *DashboardMetrics, productID int64) error {
	var scan, verification sql.NullString
	err := r.db.QueryRowContext(ctx, `SELECT
		(SELECT MAX(datetime(completed_at)) FROM engagements
		 WHERE status = 'completed' AND (? = 0 OR product_id = ?)),
		(SELECT MAX(datetime(COALESCE(verification_last_success_at,
		 CASE WHEN verification_status IN ('fixed', 'not_fixed') THEN verification_last_run_at END))) FROM findings
		 WHERE (? = 0 OR product_id = ?))`,
		productID, productID, productID, productID).Scan(&scan, &verification)
	if err != nil {
		return err
	}
	metrics.LastSuccessfulScanAt = freshnessTimestamp(scan)
	metrics.LastSuccessfulVerificationAt = freshnessTimestamp(verification)
	return nil
}

func freshnessTimestamp(value sql.NullString) *string {
	if !value.Valid {
		return nil
	}
	parsed, err := time.Parse("2006-01-02 15:04:05", value.String)
	if err != nil {
		return nil
	}
	formatted := parsed.UTC().Format(time.RFC3339)
	return &formatted
}
