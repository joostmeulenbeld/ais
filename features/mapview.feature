Feature: Map View
  In order to asses the situation in my area
  As a coast guard
  I want to see the location of each vessel marked on a map

  Scenario: show map
     When I view the homepage
     Then I should see a map of the area around "51.9N, 4.35E"

  Scenario: show vessel inside map area
    Given class "A" vessel "Seal" at position "52.01N, 3.99E"
      And class "B" vessel "Seagull" at position "52.0N, 4.0E"
     When I see the map area between "52.10N, 3.90E" and "51.90N, 4.10E"
     Then I should see a vessel at position "52.01N, 3.99E"
      And I should see a vessel at position "52.0N, 4.0E"

  Scenario: vessels outside the map area should not be visible
    Given class "A" vessel "Seagull" at position "51.97N, 3.12E"
     When I see the map area between "52.10N, 3.90E" and "51.90N, 4.10E"
     Then I should not see vessel "Seagull"