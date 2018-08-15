package main

import (
    "fmt"
    "html/template"
    "log"
    "net/http"
    "strconv"
)

func StartWeb() {
	http.HandleFunc("/", handler)
	log.Fatal(http.ListenAndServe("127.0.0.1:8080", nil))
}

func handler(w http.ResponseWriter, r *http.Request) {
	logger.Println("Request", r.URL.Path)

	switch r.Method {
	case "POST":
		if err := r.ParseForm(); err != nil {
			fmt.Fprintf(w, "ParseForm() err: %v", err)
			return
		}
		logger.Println("Post", r.PostForm)

		switch r.FormValue("action") {
		case "start-monitor":
			startMonitor(r.FormValue("devicename"), r.FormValue("ip"), r.FormValue("netmask"), r.FormValue("mac"))
		case "stop-monitor":
			i, err := strconv.Atoi(r.FormValue("idx"))
			if err != nil {
				log.Fatal(err)
			}
			stopMonitor(i)
		}
	}
    t, err := template.ParseFiles("main.html")
    if err != nil {
    	log.Fatal(err)
    }
    t.Execute(w, appstate)
}
