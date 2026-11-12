extends SceneTree
# Prints a line from res://data.txt so a run of the pack proves Godot read it.
func _init():
	var f = File.new()
	if f.open("res://data.txt", File.READ) == OK:
		print("REVLENS-PCK ", f.get_line())
	else:
		print("REVLENS-PCK missing")
	quit()
