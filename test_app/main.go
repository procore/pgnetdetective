package main

import (
	"database/sql"
	"fmt"
	"math/rand"
	"time"

	_ "github.com/lib/pq"
)

type ApplePicker struct {
	Id           string
	Name         string
	ApplesPicked int
}

func (ap *ApplePicker) PickApple(db *sql.DB) error {
	ap.ApplesPicked += 1

	tx, err := db.Begin()
	if err != nil {
		return err
	}

	_, err = db.Exec(`
		UPDATE apple_picker
		SET apples_picked = $1
		WHERE id = $2
	`, ap.ApplesPicked, ap.Id,
	)

	if err != nil {
		fmt.Printf("Error committing submission %v to database: %s", ap, err)
		rollbackErr := tx.Rollback()
		if rollbackErr != nil {
			return rollbackErr
		}
		return err
	}

	if err = tx.Commit(); err != nil {
		err = fmt.Errorf("Error committing submission %v to database: %s", ap, err)
		return err
	}

	return nil
}

func (ap *ApplePicker) StartPicking(db *sql.DB) {
	for {
		err := ap.PickApple(db)
		if err != nil {
			panic(err)
		}
		time.Sleep(time.Duration(rand.Intn(3)) * time.Second)
	}
}

func getAllApplePickers(db *sql.DB) ([]*ApplePicker, error) {
	rows, err := db.Query("SELECT id, name, apples_picked FROM apple_picker")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	allApplePickers := []*ApplePicker{}
	for rows.Next() {
		applePicker := &ApplePicker{}

		err := rows.Scan(&applePicker.Id, &applePicker.Name, &applePicker.ApplesPicked)
		if err != nil {
			return nil, err
		}

		allApplePickers = append(allApplePickers, applePicker)
	}

	return allApplePickers, nil
}

func getTopApplePicker(db *sql.DB) (*ApplePicker, error) {
	topApplePicker := &ApplePicker{}
	err := db.QueryRow(`
		SELECT id, name, apples_picked
		FROM apple_picker
		ORDER BY apples_picked DESC
		LIMIT 1
	`).Scan(&topApplePicker.Id, &topApplePicker.Name, &topApplePicker.ApplesPicked)

	if err != nil {
		return nil, err
	}

	return topApplePicker, nil
}

func main() {
	rand.Seed(time.Now().Unix())

	fmt.Println("Connecting to the database...")
	db, err := sql.Open("postgres", "postgres://pgnet:pgnet@127.0.0.1:5432/apple_picker_extreme?sslmode=disable")
	if err != nil {
		panic(err)
	}
	defer db.Close()

	fmt.Println("Getting apple pickers...")
	allApplePickers, err := getAllApplePickers(db)
	if err != nil {
		panic(err)
	}

	for _, applePicker := range allApplePickers {
		go applePicker.StartPicking(db)
	}
	fmt.Println("Picking has started!")

	for {
		topApplePicker, err := getTopApplePicker(db)
		if err != nil {
			panic(err)
		}

		fmt.Printf("The current winner is %s with %d apples picked!\n",
			topApplePicker.Name, topApplePicker.ApplesPicked,
		)

		time.Sleep(5 * time.Second)
	}

}
