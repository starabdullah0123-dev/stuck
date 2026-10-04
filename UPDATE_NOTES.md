# UNITED KERALAM update

Implemented:
- Legendary Track Record trophy/timeline entries are clickable and open the matching tournament profile's Trophy tab; matching tournament year is used when available.
- Trophy category entries are clickable and open the matching tournament Trophy tab.
- Tournament page is a responsive list with format filters: All, Test, ODI, T20. Tournament rows open individual tournament profiles.
- Tournament CRUD remains available in Edit mode.
- Tournament profile now includes a Trophy tab alongside Insights, Batting, Bowling, Fielding, Top Performers and Champions.
- Player Rankings team names are clickable and open the team profile.
- Team profiles now have a Statistics tab immediately after Matches.
- Statistics follows the supplied reference layout: Matches/Won/Win %, Lost/Tie/Draw/NR, Team Score High/Low, and Toss Won/Bat First/Bowl First.
- Statistics supports Overall/Test/ODI/T20 and year selection.
- Statistics can be edited in Edit mode and persists locally or through the existing server settings table.
- Responsive PC/mobile styling added for tournament lists and team statistics.

## Venue Match CRUD
- Each venue now has a dedicated venue profile with a Matches section.
- Edit mode shows Add Match, Edit, and Delete controls for matches assigned to that venue.
- Add Match from a venue pre-fills that venue name.
- Match records use the existing `/api/matches` CRUD endpoints and PostgreSQL when backend mode is enabled.
- Past matches are labelled HISTORY; future matches are labelled UPCOMING.
