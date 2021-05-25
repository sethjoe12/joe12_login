package middleware

import (
	"net/http"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/globalsign/mgo"
	"github.com/globalsign/mgo/bson"
	"github.com/jackyzha0/go-auth-w-mongo/db"
	"github.com/jackyzha0/go-auth-w-mongo/schemas"
)

func Auth(req http.HandlerFunc, adminCheck bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c, cookieFetchErr := r.Cookie("session_token")

		if cookieFetchErr != nil {
			if cookieFetchErr == http.ErrNoCookie {
				http.Redirect(w, r, "/login", http.StatusSeeOther)
				return
			}
			w.WriteHeader(http.StatusBadRequest)
			log.Warn("Bad Auth Attempt: Could not read cookie.")
			return
		}

		sessionToken := c.Value

		filter := bson.M{"sessionToken": sessionToken}
		var res schemas.User
		findErr := db.Users.Find(filter).One(&res)

		if findErr != nil {

			if findErr == mgo.ErrNotFound {
				http.Redirect(w, r, "/login", http.StatusSeeOther)
				log.Warnf("Bad Auth Attempt: No user with token %s.", sessionToken)
				return
			}

			w.WriteHeader(http.StatusInternalServerError)
			log.Warn("Bad Auth Attempt: Internal Error when finding user.")
			return
		}

		expireTime, timeParseErr := time.Parse(time.RFC3339, res.SessionExpires)

		if timeParseErr != nil {
			w.WriteHeader(http.StatusBadRequest)
			log.Warn("Bad Auth Attempt: Session expiry date wrong.")
			return
		}

		if time.Now().After(expireTime) {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		if adminCheck && !res.IsAdmin {
			w.WriteHeader(http.StatusUnauthorized)
			log.Warn("Bad Auth Attempt: Not admin. Attempt from user %v", res.Email)
			return
		}

		r.Header.Set("X-res-email", res.Email)
		req(w, r)
	}
}
