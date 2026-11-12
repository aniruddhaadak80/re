extends SceneTree
# Prints a line from res://data.txt so a run of the embedded pack proves Godot read it.
func _init():
	var f = FileAccess.open("res://data.txt", FileAccess.READ)
	print("REVLENS-PCK ", f.get_line() if f else "missing")
	quit()
