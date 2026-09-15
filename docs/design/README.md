# Design

`console/` holds the source of the Clavis UI design canvas: one `.dc.html`
file per artboard and `canvas.json` for their layout, pages and notes. The
canvas itself is published at https://claude.ai/artifact/AhUQ1bKKkZeMfAVJ1HPqzi
and is the place to look at or edit the design; these files are its saved
state so the work survives outside that page and can be rebuilt from here.

Pages on the canvas:

- **Clavis UI**: the shipped console direction (sign-in, Users, Connections,
  Grants, dark appearance).
- **Groups and access**: the chosen rework of September 15, 2026. The Grants
  page goes away; a group opens to Members and Connections tabs, a user to
  Groups and Access tabs (each connection with the path it comes through), and
  a connection gains an Access tab listing the groups granted and every person
  who can use it. Not yet implemented.
- **Other directions**: console styles and grants-page layouts that were not
  chosen, kept for reference.

To continue the design from these files, ask the assistant to open the canvas
from `docs/design/console`; it reassembles the page from the artboards and
saves it to the same link.
