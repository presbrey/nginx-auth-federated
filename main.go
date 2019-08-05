package main

import (
	"bytes"
	"crypto/sha1"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/http/fcgi"
	"strings"
	"time"

	"github.com/jcalabro/ldap"
)

var (
	bind  = flag.String("bind", "", "")
	userf = flag.String("U", "uid=%s,cn=users,cn=accounts,dc=example,dc=com", "username template")
	realm = flag.String("r", "EXAMPLE.COM", "authentication realm")
	host  = flag.String("h", "ldap.example.com", "LDAP server host")
	port  = flag.Uint("p", 636, "LDAP server port")
	ttl   = flag.Duration("t", 60*time.Second, "cache TTL")

	oneloginCookie = flag.String("cookie", "auth", "")
	oneloginMaxAge = flag.Int("maxage", 86400, "OneLogin FedAuth validity period")
	oneloginToken  = flag.String("token", "", "OneLogin FedAuth token")

	ErrNoAuth       = errors.New("http: no or invalid authorization header")
	ErrHost         = errors.New("http: no credential for provided host")
	authorization   = "Authorization"
	wwwAuthenticate = "Www-Authenticate"
)

func init() {
	flag.Parse()
}

type Server struct{}
type entry struct {
	valid bool
	until time.Time
}

var cache = make(map[string]*entry)
var tlsConfig = &tls.Config{InsecureSkipVerify: true}
var server = &Server{}

func (s *Server) authenticate(username, password string) (r bool, e error) {
	l := ldap.NewLDAPTLSConnection(*host, uint16(*port), tlsConfig)
	e = l.Connect()
	if e != nil {
		return
	}

	defer l.Close()
	dn := fmt.Sprintf(*userf, username)
	e = l.Bind(dn, password)

	if e == nil {
		r = true
	}
	return
}

func splitAuth(h string) (string, []byte, error) {
	i := strings.Index(h, " ")
	if i < 0 {
		return "", nil, ErrNoAuth
	}

	data, err := base64.StdEncoding.DecodeString(h[i+1:])
	return h[:i+1], data, err
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if len(*oneloginToken) > 0 {
		auth, _ := r.Cookie(*oneloginCookie)
		if auth != nil {
			lst := strings.Split(auth.Value, "|")
			if len(lst) > 1 {
				key := sha1.New()
				key.Write([]byte(lst[0] + *oneloginToken))
				if hex.EncodeToString(key.Sum(nil)) == lst[1] {
					w.WriteHeader(200)
					return
				}
			}
		}

		firstname := r.FormValue("firstname")
		lastname := r.FormValue("lastname")
		email := r.FormValue("email")
		timestamp := r.FormValue("timestamp")
		signature := r.FormValue("signature")
		key := sha1.New()
		key.Write([]byte(firstname + lastname + email + timestamp + *oneloginToken))
		keyx := hex.EncodeToString(key.Sum(nil))

		if keyx == signature {
			http.SetCookie(w, &http.Cookie{
				Name:   *oneloginCookie,
				Value:  firstname + lastname + email + timestamp + "|" + signature,
				MaxAge: *oneloginMaxAge,
			})
			w.WriteHeader(200)
			return
		}
	}

	w.Header().Add(wwwAuthenticate, fmt.Sprintf("Basic realm=\"%s\"", *realm))
	_, data, err := splitAuth(r.Header.Get(authorization))
	if err != nil {
		w.WriteHeader(401)
		return
	}

	t := time.Now()
	k := string(data)
	e, ex := cache[k]
	if ex && e.valid && t.Before(e.until) {
		w.WriteHeader(200)
		return
	}

	i := bytes.IndexRune(data, ':')
	if i < 0 {
		w.WriteHeader(401)
		return
	}
	username, password := string(data[:i]), string(data[i+1:])
	valid, err := s.authenticate(username, password)
	if valid {
		cache[k] = &entry{valid: true, until: t.Add(*ttl)}
		w.WriteHeader(200)
	} else {
		w.WriteHeader(401)
	}
}

func main() {
	if *bind == "" {
		log.Fatalln(fcgi.Serve(nil, server))
	} else {
		log.Fatalln(http.ListenAndServe(*bind, server))
	}
}
