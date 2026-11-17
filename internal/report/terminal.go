package report

import (
	"fmt"
	"io"
	"os"
	"strings"
)

const reset = "\033[0m"
const green = "\033[32m"
const cyan = "\033[36m"
const red = "\033[31m"
const yellow = "\033[33m"
const dim = "\033[2m"

func colorEnabled(w io.Writer) bool {
	f, ok := w.(*os.File)
	return ok && os.Getenv("NO_COLOR") == "" && os.Getenv("TERM") != "dumb" && f != nil
}

func paint(w io.Writer, color, s string) string {
	if !colorEnabled(w) {
		return s
	}
	return color + s + reset
}

func Banner(w io.Writer) {
	fmt.Fprintln(w, paint(w, green, `███╗   ██╗███████╗████████╗`))
	fmt.Fprintln(w, paint(w, green, `████╗  ██║██╔════╝╚══██╔══╝`))
	fmt.Fprintln(w, paint(w, green, `██╔██╗ ██║█████╗     ██║`))
	fmt.Fprintln(w, paint(w, green, `██║╚██╗██║██╔══╝     ██║`))
	fmt.Fprintln(w, paint(w, green, `██║ ╚████║███████╗   ██║`))
	fmt.Fprintln(w, paint(w, green, `╚═╝  ╚═══╝╚══════╝   ╚═╝`))
	fmt.Fprintln(w)
	fmt.Fprintf(w, "  %s  %s\n", paint(w, cyan, "NETWATCH"), paint(w, dim, "NETWORK SECURITY ANALYZER · v1.0.0"))
	fmt.Fprintln(w, paint(w, dim, strings.Repeat("─", 48)))
}

func section(w io.Writer, title string) { fmt.Fprintf(w, "\n%s\n", paint(w, cyan, title)) }
func riskColor(risk string) string {
	if risk == "HIGH" || risk == "CRITICAL" {
		return red
	}
	if risk == "MEDIUM" {
		return yellow
	}
	return green
}
