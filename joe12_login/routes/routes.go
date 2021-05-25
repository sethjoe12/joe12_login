package routes

import (
	"fmt"
	"net/http"
	"time"

	log "github.com/sirupsen/logrus"

	uuid "github.com/gofrs/uuid"
	"github.com/jackyzha0/go-auth-w-mongo/db"
	"github.com/jackyzha0/go-auth-w-mongo/schemas"

	"github.com/globalsign/mgo/bson"

	"github.com/gorilla/schema"
	"golang.org/x/crypto/bcrypt"
)

func refreshToken(email string) (c *http.Cookie, ok bool) {

	sessionToken, _ := uuid.NewV4()
	expiry := time.Now().Add(120 * time.Minute)
	expiryStr := expiry.Format(time.RFC3339)

	update := bson.M{
		"$set": bson.M{"sessionToken": sessionToken.String(),
			"sessionExpires": expiryStr}}
	updateErr := db.Users.Update(bson.M{"email": email}, update)

	if updateErr != nil {
		return nil, false
	}

	log.Infof("Refreshing token for user %v", email)
	return &http.Cookie{
		Name:    "session_token",
		Value:   sessionToken.String(),
		Expires: expiry,
	}, true
}

func Login(w http.ResponseWriter, r *http.Request) {
	creds := new(schemas.Credentials)

	parseFormErr := r.ParseForm()
	if parseFormErr != nil {

		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, "error: %v", parseFormErr)
		return
	}

	decoder := schema.NewDecoder()
	parseErr := decoder.Decode(creds, r.PostForm)
	if parseErr != nil {

		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, "error: %v", parseErr)
		return
	}

	log.Infof("Login attempt from %v", creds.Email)

	filter := bson.M{"email": creds.Email}
	var res schemas.User
	findErr := db.Users.Find(filter).One(&res)

	if findErr != nil {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	gotPass := []byte(creds.Password)
	dbPass := []byte(res.Password)
	compErr := bcrypt.CompareHashAndPassword(dbPass, gotPass)

	if compErr != nil {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	c, ok := refreshToken(res.Email)

	if !ok {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, c)

	http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
}

func Logout(w http.ResponseWriter, r *http.Request) {
	e := r.Header.Get("X-res-email")

	update := bson.M{
		"$set": bson.M{"sessionToken": ""}}
	updateErr := db.Users.Update(bson.M{"email": e}, update)

	if updateErr != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
}

func Register(w http.ResponseWriter, r *http.Request) {
	newUser := new(schemas.User)
	parseFormErr := r.ParseForm()
	if parseFormErr != nil {

		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, "error: %v", parseFormErr)
		return
	}

	decoder := schema.NewDecoder()
	parseErr := decoder.Decode(newUser, r.PostForm)
	if parseErr != nil {

		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, "error: %v", parseErr)
		return
	}

	hash, hashErr := bcrypt.GenerateFromPassword([]byte(newUser.Password), bcrypt.MinCost)
	if hashErr != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	newUser.Password = string(hash)

	insertErr := db.Users.Insert(newUser)

	if insertErr != nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, "Bad Request, user with that email exists.\n")
		return
	}

	w.WriteHeader(http.StatusOK)
	log.Infof("Created new user with email %v", newUser.Email)
}

func Dashboard(w http.ResponseWriter, r *http.Request) {
	e := r.Header.Get("X-res-email")
	var res schemas.User
	_ = db.Users.Find(bson.M{"email": e}).One(&res)

	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "Welcome back %s!\n", res.Name)
}
