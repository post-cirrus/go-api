package main

import (
    "encoding/json" // JSON format
    "log"
    "net/http" // HTTP listener
    "github.com/gorilla/mux" // HTTP request multiplexer
    "io/ioutil" // I/O tools
)

// Variable init
type Chain struct {
		Name  string `json:"name,omitempty"` // INPUT, OUTPUT, FORWARD, ...
		Rules []Rule `json:"rules,omitempty"` // List of rules within the particular chain
}

type Rule struct {
		Num         string `json:"num,omitempty"` // Rule number within the particular chain
		Target      string `json:"target,omitempty"` // ACCEPT, REJECT
		Prot        string `json:"prot,omitempty"` // Protocols. tcp, udp, icmp, ...
		Opt         string `json:"opt,omitempty"` // Special options for that specific rule.
    Source      string `json:"source,omitempty"` // Source ip-address of the packet
    Destination string `json:"destination,omitempty"` // Destination ip-address for the packet
}

type SnortRule struct {
		Action    string `json:"action,omitempty"` // activate, alert, ...
		Proto     string `json:"proto,omitempty"` // tcp, udp, ...
		Src_ip    string `json:"sourceIp,omitempty"` // Protocols. tcp, udp, icmp, ...
		Src_port  string `json:"sourcePort,omitempty"` // Source ip-address of the packet
    Direction string `json:"direction,omitempty"` // Source port of the packet
    Dst_ip    string `json:"destionationIp,omitempty"` // Destination ip-address for the packet
    Dst_port  string `json:"destinationPort,omitempty"` // Destination port for the packet
    Options   string `json:"options,omitempty"` // additional options
}

var chains []Chain
var snortRules []SnortRule

// private functions
func check(e error) {
    if e != nil {
        panic(e)
    }
}

// API functions
func WriteToFile(w http.ResponseWriter, r *http.Request) {
  params := mux.Vars(r)

  if params["filename"] == "local.rules" {
    for _, rule := range snortRules {
      stringRule := rule.Action + " " + rule.Proto + " " + rule.Src_ip + " " + rule.Src_port + " " + rule.Direction + " " + rule.Dst_ip + " " + rule.Dst_port + " " + rule.Options
      err := InsertStringToFile(params["filename"], stringRule + "\n", 0)
      check(err)
    }
  } else {
    for _, chain := range chains {
      for _, rule := range chain.Rules {
        stringRule := rule.Num + " " + rule.Target + " " + rule.Prot + " " + rule.Opt + " " + rule.Source + " " + rule.Destination
        err := InsertStringToFile(params["filename"], stringRule + "\n", 0)
        check(err)
      }
    }
  }
}

func GetFileContent(w http.ResponseWriter, r *http.Request) {
  params := mux.Vars(r)
	dat, err := ioutil.ReadFile(params["filename"])
  check(err)
	json.NewEncoder(w).Encode(string(dat))
}

func GetRules(w http.ResponseWriter, r *http.Request) {
  w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(chains)
}
// func CreateRules(w http.ResponseWriter, r *http.Request) {}
// func DeleteRules(w http.ResponseWriter, r *http.Request) {}

func GetSnortRules(w http.ResponseWriter, r *http.Request) {
  w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(snortRules)
}

// main function
func main() {
    router := mux.NewRouter()
    router.HandleFunc("/writeFile/{filename}", WriteToFile).Methods("GET")
		router.HandleFunc("/readFile/{filename}", GetFileContent).Methods("GET")

    // Iptables API
		router.HandleFunc("/iptables", GetRules).Methods("GET")
    // router.HandleFunc("/iptables/{id}", CreateRules).Methods("POST")
    // router.HandleFunc("/iptables/{id}", DeleteRules).Methods("DELETE")

    // Snort API
    router.HandleFunc("/snort", GetSnortRules).Methods("GET")

		// manual objects (later from DB or file)
		chains = append(chains, Chain{Name: "INPUT",Rules: []Rule{
        Rule{Num: "1", Target: "ACCEPT", Prot: "all", Opt: "--", Source: "0.0.0.0/0", Destination: "0.0.0.0/0"},
        Rule{Num: "2", Target: "DENY", Prot: "all", Opt: "--", Source: "0.0.0.0/0", Destination: "0.0.0.0/0"}}})
		chains = append(chains, Chain{Name: "OUTPUT", Rules: []Rule{ Rule{Num: "1", Target: "ACCEPT", Prot: "all", Opt: "--", Source: "0.0.0.0/0", Destination: "0.0.0.0/0"}}})
		chains = append(chains, Chain{Name: "FORWARD", Rules: []Rule{ Rule{Num: "1", Target: "ACCEPT", Prot: "all", Opt: "--", Source: "0.0.0.0/0", Destination: "0.0.0.0/0"}}})

    snortRules = append(snortRules, SnortRule{Action: "alert", Proto: "tcp", Src_ip: "$HOME_NET", Src_port: "any", Direction: "->", Dst_ip: "any", Dst_port: "any", Options : "(msg:\"[SNORT] Facebook detected!\";content:\"facebook\"; nocase; sid:1000004;)"})
    snortRules = append(snortRules, SnortRule{Action: "alert", Proto: "tcp", Src_ip: "$HOME_NET", Src_port: "any", Direction: "->", Dst_ip: "any", Dst_port: "any", Options : "(msg:\"[SNORT] Twitter detected!\";content:\"twitter\"; nocase; sid:1000005;)"})
    snortRules = append(snortRules, SnortRule{Action: "alert", Proto: "tcp", Src_ip: "$EXTERNAL_NET", Src_port: "any", Direction: "->", Dst_ip: "$HOME_NET", Dst_port: "any", Options : "(msg:\"[SNORT] SCORE! Get the lotion! [Porn]\"; content: \"porn\"; nocase; sid: 5001008;)"})
    snortRules = append(snortRules, SnortRule{Action: "alert", Proto: "tcp", Src_ip: "10.99.1.1", Src_port: "any", Direction: "->", Dst_ip: "any", Dst_port: "53", Options : "(msg:\"[SNORT] DNS Request\";content:\"facebook\"; nocase; sid:1000009;)"})


		log.Fatal(http.ListenAndServe(":8000", router)) // must be last
}
