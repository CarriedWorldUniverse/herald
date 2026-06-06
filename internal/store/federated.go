package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
)

func (s *SQLite) RegisterIssuer(ctx context.Context, iss Issuer) (Issuer, error) {
	if iss.ID == "" {
		iss.ID = newID()
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO issuer (id, org_id, kind, ref) VALUES (?, ?, ?, ?)`,
		iss.ID, iss.OrgID, iss.Kind, iss.Ref)
	if err != nil {
		return Issuer{}, fmt.Errorf("RegisterIssuer: %w", err)
	}
	return s.getIssuer(ctx, iss.ID)
}

func (s *SQLite) AddBinding(ctx context.Context, b FederatedBinding) (FederatedBinding, error) {
	if b.ID == "" {
		b.ID = newID()
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO federated_binding (id, org_id, user_id, issuer_id, subject)
		 VALUES (?, ?, ?, ?, ?)`,
		b.ID, b.OrgID, b.UserID, b.IssuerID, b.Subject)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint failed: federated_binding.org_id, federated_binding.issuer_id, federated_binding.subject") {
			return FederatedBinding{}, ErrDuplicateFederatedBinding
		}
		return FederatedBinding{}, fmt.Errorf("AddBinding: %w", err)
	}
	return s.getBinding(ctx, b.ID)
}

func (s *SQLite) ResolveBinding(ctx context.Context, orgID, issuerID, subject string) (string, error) {
	var userID string
	err := s.db.QueryRowContext(ctx,
		`SELECT user_id FROM federated_binding
		  WHERE org_id = ? AND issuer_id = ? AND subject = ?`,
		orgID, issuerID, subject).Scan(&userID)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	}
	if err != nil {
		return "", fmt.Errorf("ResolveBinding: %w", err)
	}
	return userID, nil
}

func (s *SQLite) getIssuer(ctx context.Context, id string) (Issuer, error) {
	var iss Issuer
	err := s.db.QueryRowContext(ctx,
		`SELECT id, org_id, kind, ref, created_at FROM issuer WHERE id = ?`, id).
		Scan(&iss.ID, &iss.OrgID, &iss.Kind, &iss.Ref, &iss.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return Issuer{}, ErrNotFound
	}
	if err != nil {
		return Issuer{}, fmt.Errorf("getIssuer: %w", err)
	}
	return iss, nil
}

func (s *SQLite) getBinding(ctx context.Context, id string) (FederatedBinding, error) {
	var b FederatedBinding
	err := s.db.QueryRowContext(ctx,
		`SELECT id, org_id, user_id, issuer_id, subject, created_at
		   FROM federated_binding WHERE id = ?`, id).
		Scan(&b.ID, &b.OrgID, &b.UserID, &b.IssuerID, &b.Subject, &b.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return FederatedBinding{}, ErrNotFound
	}
	if err != nil {
		return FederatedBinding{}, fmt.Errorf("getBinding: %w", err)
	}
	return b, nil
}
