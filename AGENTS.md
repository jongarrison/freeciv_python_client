* This repository is related to the open source freeciv game project: https://github.com/freeciv/freeciv.git (git submodule is checked out at ./freeciv-src)

* This repository aims to create a python based client for interacting with a running server found at the connection information specified in ./secrets/

* The goal is to create reusable python client code that that obtain detailed game state for the specified player and make moves on the player's behalf.

* Experiments with interacting with the server should be captured in reusable functions so that hard won protocol knowledge is captured for easy future reuse.

* Reading and summary of game state information should support the strategies mentioned in the TURN_GUIDE.html. The TURN_GUIDE.html should be edited as turn strategies are improved.

* Protocol explorations experiments should be balanced between trial and error requests to the server AND investigation of the known server source code.

* move successful experiments in to reusable functions that are used by other functions needing the same functionality. Write composeable, elegant code.

* Do not write large summary files unless requested. Make concise code comments for each function that describe the usage and intent of the function.
