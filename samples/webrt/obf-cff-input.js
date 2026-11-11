// Known input for the control flow flattening fixture (var keeps statements flattenable).
function run(a) {
  var x = a + 1;
  console.log('step one', x);
  var y = x * 2;
  console.log('step two', y);
  var z = y - 3;
  console.log('step three', z);
  return z;
}
run(5);
