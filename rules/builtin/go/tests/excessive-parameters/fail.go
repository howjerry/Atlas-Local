// Excessive Parameters: SHOULD trigger the rule
// Pattern: Functions with 6 or more parameter declarations

package main

func createUser(name string, email string, age int, role string, team string, active bool) {
	_ = name
	_ = email
	_ = age
	_ = role
	_ = team
	_ = active
}

func sendEmail(from string, to string, cc string, subject string, body string, attachment string) {
	_ = from
	_ = to
	_ = cc
	_ = subject
	_ = body
	_ = attachment
}
