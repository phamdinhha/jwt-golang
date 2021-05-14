package controllers

import (
	"context"
	"errors"
	"example/jwt/database"
	"example/jwt/models"
	"fmt"
	"strconv"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gofiber/fiber/v2"
	uuid "github.com/satori/go.uuid"
	"golang.org/x/crypto/bcrypt"
)

//should be env variable
const ACCESS_SECRET = "access_secret"
const REFRESH_SECRET = "refresh_secret"

// os.Setenv("ACCESS_SECRET", "haphamd-vinbigdata")

func Hello(c *fiber.Ctx) error {
	return c.SendString("Hello world!")
}

func CreateToken(userid uint64) (*models.TokenDetails, error) {
	td := &models.TokenDetails{}
	td.AtExpires = time.Now().Add(time.Hour * 24).Unix()
	td.AccessUuid = uuid.NewV4().String()
	td.RtExpires = time.Now().Add(time.Hour * 24 * 7).Unix()
	td.RefreshUuid = td.AccessUuid + "++" + strconv.Itoa(int(userid))

	var err error
	// access token
	at := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"authorized":  true,
		"access_uuid": td.AccessUuid,
		"user_id":     userid,
		"exp":         td.AtExpires,
	})
	td.AccessToken, err = at.SignedString([]byte(ACCESS_SECRET))
	if err != nil {
		return nil, err
	}

	//refresh token
	rt := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"refresh_uuid": td.RefreshUuid,
		"user_id":      userid,
		"exp":          td.RtExpires,
	})
	td.RefreshToken, err = rt.SignedString([]byte(REFRESH_SECRET))
	if err != nil {
		return nil, err
	}
	return td, nil
}

func CreateAuth(userid int64, td *models.TokenDetails) error {
	at := time.Unix(td.AtExpires, 0)
	rt := time.Unix(td.RtExpires, 0)
	now := time.Now()
	ctx := context.TODO()

	errAccess := database.RDB.Set(ctx, td.AccessUuid, strconv.Itoa(int(userid)), at.Sub(now)).Err()
	if errAccess != nil {
		return errAccess
	}

	errRefresh := database.RDB.Set(ctx, td.RefreshUuid, strconv.Itoa(int(userid)), rt.Sub(now)).Err()
	if errRefresh != nil {
		return errRefresh
	}
	return nil
}

func Register(c *fiber.Ctx) error {
	var data map[string]string
	if err := c.BodyParser(&data); err != nil {
		return err
	}
	//hashing password
	password, _ := bcrypt.GenerateFromPassword([]byte(data["password"]), 14)
	user := models.User{
		Name:     data["name"],
		Email:    data["email"],
		Password: password,
	}
	database.DB.Create(&user)
	return c.JSON(user)
}

func Login(c *fiber.Ctx) error {
	var data map[string]string

	if err := c.BodyParser(&data); err != nil {
		return err
	}
	var user models.User

	database.DB.Where("email = ?", data["email"]).First(&user)
	if user.Id == 0 {
		c.Status(fiber.StatusNotFound)
		return c.JSON(fiber.Map{
			"message": "user not found",
		})
	}

	err := bcrypt.CompareHashAndPassword(user.Password, []byte(data["password"]))

	if err != nil {
		c.Status(fiber.StatusBadRequest)
		return c.JSON(fiber.Map{
			"message": "incorect password",
		})
	}

	// clams := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.StandardClaims{
	// 	Issuer:    strconv.Itoa(int(user.Id)),
	// 	ExpiresAt: time.Now().Add(time.Hour * 24).Unix(),
	// })

	// token, err := clams.SignedString([]byte(ACCESS_SECRET))

	ts, err := CreateToken(uint64(user.Id))

	if err != nil {
		c.Status(fiber.StatusInternalServerError)
		return c.JSON(fiber.Map{
			"message": err.Error(),
		})
	}

	saveErr := CreateAuth(int64(user.Id), ts)

	if saveErr != nil {
		c.Status(fiber.StatusInternalServerError)
		return c.JSON(fiber.Map{
			"message": saveErr.Error(),
		})
	}

	//cookie to store access token
	cookie := fiber.Cookie{
		Name:     "jwt",
		Value:    ts.AccessToken,
		Expires:  time.Unix(ts.AtExpires, 0),
		HTTPOnly: true,
	}

	//cookie to store refresh token
	cookie_refresh := fiber.Cookie{
		Name:     "jwt_refresh",
		Value:    ts.RefreshToken,
		Expires:  time.Unix(ts.RtExpires, 0),
		HTTPOnly: true,
	}

	c.Cookie(&cookie)
	c.Cookie(&cookie_refresh)

	// tokens := fiber.Map{
	// 	"access_token":  ts.AccessToken,
	// 	"refresh_token": ts.RefreshToken,
	// }

	return c.JSON(fiber.Map{
		"message": "successfully login!",
	})
}

func GetAuth(access_uuid string, userId uint64) (uint64, error) {
	ctx := context.TODO()
	userid, err := database.RDB.Get(ctx, access_uuid).Result()

	if err != nil {
		return 0, err
	}

	userIdFromDB, _ := strconv.ParseUint(userid, 10, 64)
	if userId != userIdFromDB {
		return 0, errors.New("unauthorized")
	}

	return userIdFromDB, nil
}

func GetAccessTokenFromCookies(c *fiber.Ctx) (*jwt.Token, error) {
	cookie := c.Cookies("jwt")

	token, err := jwt.ParseWithClaims(cookie, jwt.MapClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(ACCESS_SECRET), nil
	})

	return token, err
}

func User(c *fiber.Ctx) error {

	token, err := GetAccessTokenFromCookies(c, "jwt")

	if err != nil {
		c.Status(fiber.StatusUnauthorized)
		return c.JSON(fiber.Map{
			"message": "unauthorized",
		})
	}

	claims, _ := token.Claims.(jwt.MapClaims)

	userid, err := GetAuth(claims["access_uuid"].(string), claims["user_id"].(uint64))

	if err != nil {
		c.Status(fiber.StatusUnauthorized)
		return c.JSON(fiber.Map{
			"message": "unauthorized",
		})
	}

	var user models.User

	database.DB.Where("id = ?", userid).First(&user)

	return c.JSON(user)
}

//Delete token from redis db
func DeleteToken(access_uuid string, userId uint64) error {
	ctx := context.TODO()
	refreshUuid := fmt.Sprintf("%s++%d", access_uuid, userId)

	deletedAt, err := database.RDB.Del(ctx, access_uuid).Result()
	if err != nil {
		return err
	}

	deletedRt, err := database.RDB.Del(ctx, refreshUuid).Result()
	if err != nil {
		return err
	}

	if deletedAt != 1 || deletedRt != 1 {
		return errors.New("something went wrong")
	}

	return nil
}

func Logout(c *fiber.Ctx) error {

	token, err := GetAccessTokenFromCookies(c)
	claims, _ := token.Claims.(jwt.MapClaims)

	delErr := DeleteToken(claims["access_uuid"].(string), claims["user_id"].(uint64))
	if delErr != nil {
		c.Status(fiber.StatusInternalServerError)
		return c.JSON(fiber.Map{
			"message": delErr.Error(),
		})
	}

	if err != nil {
		c.Status(fiber.StatusUnauthorized)
		return c.JSON(fiber.Map{
			"message": "unauthorized",
		})
	}

	cookie := fiber.Cookie{
		Name:     "jwt",
		Value:    "",
		Expires:  time.Now().Add(-time.Hour),
		HTTPOnly: true,
	}

	cookie_refresh := fiber.Cookie{
		Name:     "jwt_refresh",
		Value:    "",
		Expires:  time.Now().Add(-time.Hour),
		HTTPOnly: true,
	}

	c.Cookie(&cookie)
	c.Cookie(&cookie_refresh)

	return c.JSON(fiber.Map{
		"message": "Successfully logged out.",
	})
}

//Refresh access token
func Refresh(c *fiber.Ctx) error {
	cookie := c.Cookies("jwt-refresh")

	token, err := jwt.ParseWithClaims(cookie, jwt.MapClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(ACCESS_SECRET), nil
	})

	if err != nil {
		c.Status(fiber.StatusUnauthorized)
		return c.JSON(fiber.Map{
			"message": "unauthorized",
		})
	}

	if _, ok := token.Claims.(jwt.Claims); !ok && !token.Valid {
		c.Status(fiber.StatusUnauthorized)
		return c.JSON(fiber.Map{
			"message": "unauthorized",
		})
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if ok && token.Valid {
		refreshUuid := claims["refresh_uuid"].(string)
		user_id := claims["user_id"].(uint64)

		deleted, delErr := DeleteAuth(refreshUuid)
		if delErr != nil || deleted == 0 {
			c.Status(fiber.StatusUnauthorized)
			return c.JSON(fiber.Map{
				"message": "unauthorized",
			})
		}

		//create new pair of token
		ts, createErr := CreateToken(user_id)
		if createErr != nil {

		}
	}
}

func DeleteAuth(target_uuid string) (int64, error) {
	ctx := context.TODO()
	deleted, err := database.RDB.Del(ctx, target_uuid).Result()
	if err != nil {
		return 0, err
	}
	return deleted, nil
}
