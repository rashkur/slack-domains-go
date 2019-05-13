package whoistools

import (
	"database/sql"
	"log"
	"os"

	_ "github.com/mattn/go-sqlite3"
)

type Datastore interface {
	AllDomainsCount() (int, error)
}

type Env struct {
	DB *sql.DB
}

// InitDb - create db and tables
func InitDb(dbpth string, table string) *Env {
	if _, err := os.Stat(dbpth); os.IsNotExist(err) {
		os.Create(dbpth)
	}

	DB, err := sql.Open("sqlite3", dbpth)
	CheckErr(err)
	// defer DB.Close()

	if err = DB.Ping(); err != nil {
		log.Panic(err)
	}

	stmt, err := DB.Prepare(table)
	CheckErr(err)

	stmt.Exec()

	return &Env{DB}
}
