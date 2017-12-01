FROM golang

WORKDIR /go/src/rest-api
COPY . .

RUN go-wrapper download github.com/gorilla/mux

RUN go-wrapper install

EXPOSE 8000

CMD ["go-wrapper", "run"] # ["rest-api"]