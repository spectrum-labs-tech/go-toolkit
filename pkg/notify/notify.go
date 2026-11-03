// Package notify posts short operational messages (a new signup, a failed job, a finished
// import) to a chat channel, so a person sees them without watching a dashboard.
//
// A Message is plain data and a Notifier delivers it. Discord, through a channel webhook, is the
// one implementation. A webhook URL carries its own secret, so nothing here ever logs it or puts
// it in an error.
//
// Messages are for people, and chat is a third party: send identifiers and links, never personal
// data. Link to where the detail lives, behind your own access control.
package notify

import "context"

// Message is one notification: a title, an optional link and text, and short labelled fields.
type Message struct {
	Title  string
	URL    string // opened by clicking the title; empty for none
	Text   string
	Fields []Field
}

// Field is one labelled value. A field with an empty value is left out.
type Field struct {
	Name  string
	Value string
}

// Notifier delivers a Message.
type Notifier interface {
	Notify(ctx context.Context, m Message) error
}
