<?php

$ITOA64 = './0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';

function base64Encode($input, $count) {
	global $ITOA64;
    $output = '';
    $i = 0;
    do {
      $value = ord($input[$i++]);
      $output .= $ITOA64[$value & 0x3f];
      if ($i < $count) {
        $value |= ord($input[$i]) << 8;
      }
      $output .= $ITOA64[($value >> 6) & 0x3f];
      if ($i++ >= $count) {
        break;
      }
      if ($i < $count) {
        $value |= ord($input[$i]) << 16;
      }
      $output .= $ITOA64[($value >> 12) & 0x3f];
      if ($i++ >= $count) {
        break;
      }
      $output .= $ITOA64[($value >> 18) & 0x3f];
    } while ($i < $count);

    return $output;
  }

$algo = 'sha512';

$password = "alias chalice anybody scoff browbeat";

$setting = '$S$EVtYc19/LM2dsCUcHLe50dXY/z9vfI6hIAgezAl3PZhbwWPJ0xUK';

$setting = substr($setting, 0, 12);

$count_log2 = strpos($ITOA64, $setting[3]);

$salt = substr($setting, 4, 8);

$count = 1 << $count_log2;

$hash = hash($algo, $salt . $password, TRUE);
do {
  $hash = hash($algo, $hash . $password, TRUE);
} while (--$count);


$len = strlen($hash);
$output = $setting . base64Encode($hash, $len);
// $this->base64Encode() of a 16 byte MD5 will always be 22 characters.
// $this->base64Encode() of a 64 byte sha512 will always be 86 characters.
$expected = 12 + ceil((8 * $len) / 6);

var_dump( (strlen($output) == $expected) ? substr($output, 0, 55) : FALSE);
