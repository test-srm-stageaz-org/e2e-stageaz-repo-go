package main

import (
	"database/sql"
	"fmt"
)

// CWE-564: SQL Injection: Hibernate
type UserDAO struct {
	db *sql.DB
}

// CWE-89: SQL Injection - Multiple variations
func (dao *UserDAO) FindUserByName(username string) (*User, error) {
	// VULNERABLE: String concatenation in SQL
	query := "SELECT * FROM users WHERE username = '" + username + "'"
	row := dao.db.QueryRow(query)
	
	user := &User{}
	err := row.Scan(&user.ID, &user.Username, &user.Email)
	return user, err
}

func (dao *UserDAO) SearchUsers(searchTerm string) ([]*User, error) {
	// VULNERABLE: Using fmt.Sprintf for SQL construction
	query := fmt.Sprintf("SELECT * FROM users WHERE username LIKE '%%%s%%'", searchTerm)
	rows, err := dao.db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	
	var users []*User
	for rows.Next() {
		user := &User{}
		rows.Scan(&user.ID, &user.Username, &user.Email)
		users = append(users, user)
	}
	return users, nil
}

// CWE-89: SQL Injection in UPDATE statement
func (dao *UserDAO) UpdateUserEmail(userID, email string) error {
	// VULNERABLE: Direct interpolation in UPDATE
	query := fmt.Sprintf("UPDATE users SET email = '%s' WHERE id = %s", email, userID)
	_, err := dao.db.Exec(query)
	return err
}

// CWE-89: SQL Injection in DELETE statement
func (dao *UserDAO) DeleteUserByName(username string) error {
	// VULNERABLE: String concatenation in DELETE
	query := "DELETE FROM users WHERE username = '" + username + "'"
	_, err := dao.db.Exec(query)
	return err
}

// CWE-89: SQL Injection in ORDER BY clause
func (dao *UserDAO) GetUsersSorted(sortColumn string) ([]*User, error) {
	// VULNERABLE: User-controlled ORDER BY
	query := fmt.Sprintf("SELECT * FROM users ORDER BY %s", sortColumn)
	rows, err := dao.db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	
	var users []*User
	for rows.Next() {
		user := &User{}
		rows.Scan(&user.ID, &user.Username, &user.Email)
		users = append(users, user)
	}
	return users, nil
}

// CWE-564: SQL Injection in dynamic table name
func (dao *UserDAO) QueryTable(tableName, condition string) (*sql.Rows, error) {
	// VULNERABLE: Dynamic table name and condition
	query := fmt.Sprintf("SELECT * FROM %s WHERE %s", tableName, condition)
	return dao.db.Query(query)
}

type User struct {
	ID       int
	Username string
	Email    string
	Password string
}

// CWE-759: Use of a One-Way Hash without a Salt
func (u *User) SetPassword(password string) {
	// VULNERABLE: Hashing without salt
	u.Password = hashPassword(password)
}

// CWE-307: Improper Restriction of Excessive Authentication Attempts
func (dao *UserDAO) Authenticate(username, password string) (bool, error) {
	// VULNERABLE: No rate limiting or account lockout
	user, err := dao.FindUserByName(username)
	if err != nil {
		return false, err
	}
	
	hashedPassword := hashPassword(password)
	return user.Password == hashedPassword, nil
}
