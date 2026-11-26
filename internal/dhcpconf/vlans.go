package dhcpconf

import (
	"context"
	"database/sql"
	"errors"
	"strings"

	"github.com/prohand/leazone/internal/ids"
	"github.com/prohand/leazone/internal/store"
)

// VLAN is a readable label for a VLAN ID.
type VLAN struct {
	ID     string `json:"id"`
	VLANID int    `json:"vlanId"`
	Name   string `json:"name"`
}

// VLANs lists the labels sorted by VLAN ID.
func (s *Store) VLANs(ctx context.Context) ([]*VLAN, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, vlan_id, name FROM vlans ORDER BY vlan_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*VLAN
	for rows.Next() {
		var v VLAN
		if err := rows.Scan(&v.ID, &v.VLANID, &v.Name); err != nil {
			return nil, err
		}
		out = append(out, &v)
	}
	return out, rows.Err()
}

func checkVLAN(vlanID int, name string) (string, error) {
	errs := Validation{}
	name = strings.TrimSpace(name)
	if vlanID < 1 || vlanID > 4094 {
		errs["vlanId"] = "VLAN entre 1 et 4094"
	}
	if name == "" || len(name) > 64 {
		errs["name"] = "nom obligatoire (64 caractères max)"
	}
	if len(errs) > 0 {
		return name, errs
	}
	return name, nil
}

// CreateVLAN adds a label.
func (s *Store) CreateVLAN(ctx context.Context, vlanID int, name string) (*VLAN, error) {
	name, err := checkVLAN(vlanID, name)
	if err != nil {
		return nil, err
	}
	v := &VLAN{ID: ids.New(), VLANID: vlanID, Name: name}
	now := s.Now().UnixMilli()
	if _, err := s.db.ExecContext(ctx, `INSERT INTO vlans(id, vlan_id, name, created_at, updated_at) VALUES (?, ?, ?, ?, ?)`,
		v.ID, vlanID, name, now, now); err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			return nil, ErrConflict{Msg: "ce VLAN a déjà un nom"}
		}
		return nil, err
	}
	return v, nil
}

// UpdateVLAN changes a label (and moves its scopes if the ID changes).
func (s *Store) UpdateVLAN(ctx context.Context, id string, vlanID int, name string) (*VLAN, error) {
	name, err := checkVLAN(vlanID, name)
	if err != nil {
		return nil, err
	}
	var old int
	if err := s.db.QueryRowContext(ctx, `SELECT vlan_id FROM vlans WHERE id = ?`, id).Scan(&old); errors.Is(err, sql.ErrNoRows) {
		return nil, store.ErrNotFound
	} else if err != nil {
		return nil, err
	}
	err = s.db.Tx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `UPDATE vlans SET vlan_id = ?, name = ?, updated_at = ? WHERE id = ?`,
			vlanID, name, s.Now().UnixMilli(), id); err != nil {
			if strings.Contains(err.Error(), "UNIQUE") {
				return ErrConflict{Msg: "ce VLAN a déjà un nom"}
			}
			return err
		}
		_, err := tx.ExecContext(ctx, `UPDATE dhcp_scopes SET vlan_id = ? WHERE vlan_id = ?`, vlanID, old)
		return err
	})
	if err != nil {
		return nil, err
	}
	return &VLAN{ID: id, VLANID: vlanID, Name: name}, nil
}

// DeleteVLAN removes a label not used by any scope.
func (s *Store) DeleteVLAN(ctx context.Context, id string) error {
	var vid, n int
	if err := s.db.QueryRowContext(ctx, `SELECT vlan_id FROM vlans WHERE id = ?`, id).Scan(&vid); errors.Is(err, sql.ErrNoRows) {
		return store.ErrNotFound
	} else if err != nil {
		return err
	}
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM dhcp_scopes WHERE vlan_id = ?`, vid).Scan(&n); err != nil {
		return err
	}
	if n > 0 {
		return ErrConflict{Msg: "des étendues utilisent ce VLAN"}
	}
	_, err := s.db.ExecContext(ctx, `DELETE FROM vlans WHERE id = ?`, id)
	return err
}
