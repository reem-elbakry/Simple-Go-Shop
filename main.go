package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/context"
	"github.com/gorilla/mux"
	"github.com/joho/godotenv"
	"golang.org/x/crypto/bcrypt"

	stripe "github.com/stripe/stripe-go"
	"github.com/stripe/stripe-go/card"
	"github.com/stripe/stripe-go/paymentintent"

	_ "github.com/lib/pq"
)

// DB Config
const (
	host     = "localhost"
	port     = 5432
	user     = "postgres"
	password = "rimoura95"
	dbname   = "go_caffe"
)

// DB vars
var db *sql.DB
var err error

// ********************************USERS HANDLERS*******************************************//
// JWT var
var JWT_KEY = []byte("jwtsecretkey")

type User struct {
	ID       int    `json: "id"`
	Name     string `json: "name"`
	Email    string `json: "email"`
	Password string `json: "password"`
	Is_admin string `json: "is_admin"`
}

// Create a struct that will be encoded to a JWT.
// We add jwt.StandardClaims as an embedded type, to provide fields like expiry time
type Claims struct {
	ID       int    `json:"id"`
	Email    string `json:"email"`
	Is_admin string `json:"is_admin"`
	jwt.StandardClaims
}

// Register User
func signUp(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	var user User
	_ = json.NewDecoder(r.Body).Decode(&user)

	insertStmt := `
		INSERT INTO users (name, email, password)
		VALUES ($1, $2, $3)
		RETURNING id`
	id := 0
	user.Password = getHash([]byte(user.Password))
	err = db.QueryRow(insertStmt, user.Name, user.Email, user.Password).Scan(&id)
	if err != nil {
		panic(err)
	}
	fmt.Println("New record ID is:", id)
	json.NewEncoder(w).Encode(user)
}

// Hash Password
func getHash(pwd []byte) string {
	hash, err := bcrypt.GenerateFromPassword(pwd, bcrypt.MinCost)
	if err != nil {
		log.Println(err)
	}
	return string(hash)
}

// Login User
func signIn(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	var user User
	var dbUser User
	json.NewDecoder(r.Body).Decode(&user)

	//Fetch User
	selectStmt := `SELECT * FROM users WHERE email = $1`
	row := db.QueryRow(selectStmt, user.Email)
	switch err := row.Scan(&dbUser.ID, &dbUser.Name, &dbUser.Email, &dbUser.Password, &dbUser.Is_admin); err {
	case sql.ErrNoRows:
		fmt.Println("User not exists!")
	case nil:
		fmt.Println("Returned use ID is:", dbUser.ID)
		userPass := []byte(user.Password)
		dbPass := []byte(dbUser.Password)
		passErr := bcrypt.CompareHashAndPassword(dbPass, userPass)
		if passErr != nil {
			log.Println(passErr)
			w.Write([]byte(`{"message":"Wrong Password!"}`))
			return
		}
		jwtToken, err := GenerateJWT(dbUser)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(`{"message":"` + err.Error() + `"}`))
			return
		}
		w.Write([]byte(`{"token":"` + jwtToken + `"}`))
		// json.NewEncoder(w).Encode(dbUser)
	default:
		panic(err)
	}

}

// Generate JWT
func GenerateJWT(user User) (string, error) {
	// Declare the expiration time of the token
	// here, we have kept it as 5 minutes
	expirationTime := time.Now().Add(5 * time.Minute)

	// Create the JWT claims, which includes the username and expiry time
	claims := &Claims{
		ID:       user.ID,
		Email:    user.Email,
		Is_admin: user.Is_admin,
		StandardClaims: jwt.StandardClaims{
			// In JWT, the expiry time is expressed as unix milliseconds
			ExpiresAt: expirationTime.Unix(),
		},
	}
	// Declare the token with the algorithm used for signing, and the claims
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	// Create the JWT string
	tokenString, err := token.SignedString(JWT_KEY)

	if err != nil {
		log.Println("Error in JWT token generation")
		return "", err
	}
	return tokenString, nil
}

//********************************PRODUCTS HANDLERS*******************************************//

type Product struct {
	ID       int    `json: "id"`
	Name     string `json: "name"`
	Category string `json: "category"`
	Price    string `json: "price"`
}

// Get All Product
func getProducts(w http.ResponseWriter, r *http.Request) {

	w.Header().Set("Content-Type", "application/json")

	var products []Product

	rows, err := db.Query("SELECT * FROM products")
	if err != nil {
		panic(err)
	}
	defer rows.Close()
	for rows.Next() {
		var product Product
		err = rows.Scan(&product.ID, &product.Name, &product.Category, &product.Price)
		if err != nil {
			panic(err)
		}
		products = append(products, product)
		fmt.Println(product)
	}
	json.NewEncoder(w).Encode(products)

	// get any error encountered during iteration
	err = rows.Err()
	if err != nil {
		panic(err)
	}
}

// Get One Product
func getProduct(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	params := mux.Vars(r) //Get Params

	//Fetch product
	selectStmt := `SELECT * FROM products WHERE id = $1`

	var product Product

	row := db.QueryRow(selectStmt, params["id"])
	switch err := row.Scan(&product.ID, &product.Name, &product.Category, &product.Price); err {
	case sql.ErrNoRows:
		fmt.Println("No rows were returned!")
	case nil:
		fmt.Println("Returned record ID is:", product.ID)
		json.NewEncoder(w).Encode(product)
	default:
		panic(err)
	}

}

// create New Product
func createProduct(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	decoded := context.Get(r, "decoded")
	user := decoded.(*Claims)

	is_admin := adminOnly(user)

	if !is_admin {
		w.Write([]byte(`{"message": admin only, unauthorized!"}`))
	} else {
		var product Product
		_ = json.NewDecoder(r.Body).Decode(&product)
		insertStmt := `
		INSERT INTO products (name, category, price)
		VALUES ($1, $2, $3)
		RETURNING id`
		id := 0

		err = db.QueryRow(insertStmt, product.Name, product.Category, product.Price).Scan(&id)
		if err != nil {
			panic(err)
		}
		fmt.Println("New record ID is:", id)
		json.NewEncoder(w).Encode(product)
	}

}

// Update Product
func updateProduct(w http.ResponseWriter, r *http.Request) {

	w.Header().Set("Content-Type", "application/json")
	params := mux.Vars(r)

	decoded := context.Get(r, "decoded")
	user := decoded.(*Claims)

	is_admin := adminOnly(user)

	if !is_admin {
		w.Write([]byte(`{"message": admin only, unauthorized!"}`))
	} else {

		var product Product
		_ = json.NewDecoder(r.Body).Decode(&product)

		sqlStatement := `
		UPDATE products
		SET price = $2
		WHERE id = $1;`
		res, err := db.Exec(sqlStatement, params["id"], product.Price)
		if err != nil {
			panic(err)
		}
		count, err := res.RowsAffected()
		if err != nil {
			panic(err)
		}
		fmt.Println(count)

		json.NewEncoder(w).Encode("Product price updated successfully.")
	}

}

// Delete Product
func deleteProduct(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	params := mux.Vars(r)

	decoded := context.Get(r, "decoded")
	user := decoded.(*Claims)

	is_admin := adminOnly(user)

	if !is_admin {
		w.Write([]byte(`{"message": admin only, unauthorized!"}`))
	} else {
		sqlStatement := `
		DELETE FROM products
		WHERE id = $1;`
		res, err := db.Exec(sqlStatement, params["id"])
		if err != nil {
			panic(err)
		}
		count, err := res.RowsAffected()
		if err != nil {
			panic(err)
		}
		fmt.Println(count)
		json.NewEncoder(w).Encode("Product deleted successfully.")
	}

}

//********************************Stripe Payments*******************************************//
//**TODO -- webhooks**/

// Create Credit Card
func addCreditCard(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	stripe.Key = "sk_test_51KwUhhJ10onrvsHLF0ekKpMQInWnrX1hFlXLbYYM6e6lwXPo2LY5JoG5Yl1SPkKgo5xk6dDAjwLkdxJdgiWzlmZH00Mu1S9t7f"

	params := &stripe.CardParams{
		//id for test customer
		Customer: stripe.String("cus_MRg8h6krPErbZg"),
		Token:    stripe.String("tok_visa"),
	}
	c, err := card.New(params)

	if err != nil {
		log.Fatal("error while trying to charge a cc", err)
	}

	log.Printf("credit created successfully %v\n", c.ID)
	json.NewEncoder(w).Encode(c)

}

// Create Payment Intent
type CreatePaymentIntentReq struct {
	PaymentMethodType string `json:"paymentMethodType"`
	Currency          string `json:"currency"`
}

func createPaymentIntent(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	stripe.Key = "sk_test_51KwUhhJ10onrvsHLF0ekKpMQInWnrX1hFlXLbYYM6e6lwXPo2LY5JoG5Yl1SPkKgo5xk6dDAjwLkdxJdgiWzlmZH00Mu1S9t7f"

	data := CreatePaymentIntentReq{}

	if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
		fmt.Println("Failed to decode.")
		json.NewEncoder(w).Encode(err)

	}

	params := &stripe.PaymentIntentParams{
		Amount:   stripe.Int64(2000),
		Currency: stripe.String(data.Currency),
		PaymentMethodTypes: []*string{
			stripe.String(data.PaymentMethodType),
		},
	}
	pi, err := paymentintent.New(params)
	if err != nil {
		json.NewEncoder(w).Encode(err)

		return
	}

	w.Write([]byte("{ClientSecret:" + pi.ClientSecret + "}"))

}

//Confirm payment on client side?

//********************************Main()******************************************//

func main() {
	//Load .env file
	err := godotenv.Load()
	if err != nil {
		fmt.Println("Error loading .env file.")
	}

	//Init Router
	router := mux.NewRouter()

	psqlInfo := fmt.Sprintf("host=%s port=%d user=%s "+
		"password=%s dbname=%s sslmode=disable",
		host, port, user, password, dbname)
	db, err = sql.Open("postgres", psqlInfo)
	if err != nil {
		panic(err)
	}
	defer db.Close()

	err = db.Ping()
	if err != nil {
		panic(err)
	}

	fmt.Println("Successfully connected!")

	//Users Routes
	router.HandleFunc("/api/users/signup", signUp).Methods("POST")
	router.HandleFunc("/api/users/signin", signIn).Methods("POST")

	//Route Handler -- EndPoints For Products
	router.HandleFunc("/api/products", getProducts).Methods("GET")
	router.HandleFunc("/api/products/{id}", protect(getProduct)).Methods("GET")
	router.HandleFunc("/api/products", protect(createProduct)).Methods("POST")
	router.HandleFunc("/api/products/{id}", protect(updateProduct)).Methods("PUT")
	router.HandleFunc("/api/products/{id}", protect(deleteProduct)).Methods("DELETE")

	//Stripe Payment Routes
	router.HandleFunc("/api/payment/add-credit-card", protect(addCreditCard)).Methods("POST")
	router.HandleFunc("/api/payment/create-payment-intent", protect(createPaymentIntent)).Methods("POST")

	//Run Server
	log.Fatal(http.ListenAndServe(":8080", router))

}

// Protect Middleware
func protect(next http.HandlerFunc) http.HandlerFunc {
	return (func(w http.ResponseWriter, r *http.Request) {
		authorizationHeader := r.Header.Get("Authorization")
		if authorizationHeader != "" {
			bearerToken := strings.Split(authorizationHeader, " ")
			if len(bearerToken) == 2 {
				claims := &Claims{}
				token, error := jwt.ParseWithClaims(bearerToken[1], claims, func(token *jwt.Token) (interface{}, error) {
					return JWT_KEY, nil
				})

				if error != nil {
					if err == jwt.ErrSignatureInvalid {
						w.WriteHeader(http.StatusUnauthorized)
						w.Write([]byte(`{"message":"jwt signature invalid, unauthorized!"}`))
						return
					}
				}

				if !token.Valid {
					w.WriteHeader(http.StatusUnauthorized)
					w.Write([]byte(`{"message":"jwt invalid, unauthorized!"}`)) //
					return
				}

				context.Set(r, "decoded", claims)
				next(w, r)

			}
		} else {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(`{"message":"jwt no exists"}`)) //
		}
	})

}

// Admin Only
func adminOnly(user *Claims) bool {
	var status bool
	status = false

	if user.Is_admin == "true" {
		status = true
	}
	return status
}
