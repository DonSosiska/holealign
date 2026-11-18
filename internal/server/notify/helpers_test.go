package notify

import "github.com/DonSosiska/holealign/internal/model"

// renderGroup is the Matrix rendering (plain body, HTML body) of a group of events.
func renderGroup(raw []model.Event) (string, string) { return formatMatrix(buildGroup(raw)) }

func renderEvent(ev model.Event) (string, string) { return renderGroup([]model.Event{ev}) }
