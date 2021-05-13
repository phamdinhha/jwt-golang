package database

import (
	"example/jwt/models"

	"gorm.io/driver/mysql"
	"gorm.io/gorm"

	"github.com/go-redis/redis/v8"
)

var DB *gorm.DB

var RDB *redis.Client

func Connect() {

	dsn := "hapham:Haphamd@95@/golang_jwt"
	db, err := gorm.Open(mysql.Open(dsn), &gorm.Config{})
	if err != nil {
		panic("Failed to connect to the database")
	}
	DB = db
	DB.AutoMigrate(&models.User{})

}

func NewRedisDB(host, port, password string) {
	client := redis.NewClient(&redis.Options{
		Addr:     host + ":" + port,
		Password: password, // no password
		DB:       0,        // use default db
	})
	RDB = client
}
