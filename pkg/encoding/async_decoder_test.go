package encoding

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestAsyncDecoder(t *testing.T) {
	t.Run("success-decode-from", func(t *testing.T) {
		heroBuf := new(bytes.Buffer)
		cityBuf := new(bytes.Buffer)
		wantHero := &Hero{Name: "Tony Stark", Alias: "Iron Man", Universe: "marvel"}
		wantCity := &City{Name: "Austin", Population: 24, StateCode: "TX"}
		_ = json.NewEncoder(heroBuf).Encode(wantHero)
		obj, err := NewAsyncDecoder().WithDecoders(newHeroDecoder(), newStateDecoder()).DecodeFrom(heroBuf)
		if err != nil {
			t.Fatal(err)
		}
		hero, ok := obj.(*Hero)
		if !ok {
			t.Fatalf("Got Type %T", obj)
		}
		if hero.Name != wantHero.Name {
			t.Fatalf("got: %v want: %v", hero, wantHero)
		}

		_ = json.NewEncoder(cityBuf).Encode(wantCity)
		obj, err = NewAsyncDecoder().WithDecoders(newHeroDecoder(), newStateDecoder()).DecodeFrom(cityBuf)
		if err != nil {
			t.Fatal(err)
		}
		city, ok := obj.(*City)
		if !ok {
			t.Fatalf("Got Type %T", obj)
		}
		if city.Name != wantCity.Name {
			t.Fatalf("got: %v want: %v", hero, wantCity)
		}
	})

}

type Hero struct {
	Name     string
	Alias    string
	Universe string
}

func checkHero(h *Hero) error {
	if h.Universe != "marvel" && h.Universe != "dc" {
		return ErrFailedCheck
	}
	return nil
}

func newHeroDecoder() *JSONWriterDecoder[Hero] {
	return NewJSONWriterDecoder[Hero]("Hero", checkHero)
}

type City struct {
	Name       string
	Population int
	StateCode  string
}

func checkState(c *City) error {
	if len(c.StateCode) != 2 {
		return ErrFailedCheck
	}
	return nil
}

func newStateDecoder() *JSONWriterDecoder[City] {
	return NewJSONWriterDecoder[City]("City", checkState)
}
