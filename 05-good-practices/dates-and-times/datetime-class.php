<?php
date_default_timezone_set('Asia/Taipei');

// Constructor
$datetime1 = new DateTime();
var_dump($datetime1);

// Constructor with argument
$datetime2 = new DateTime('2014-04-27 5:03 AM');
var_dump($datetime2);

// Static constructor with format
$datetime3 = DateTime::createFromFormat('M j, Y H:i:s', 'Jan 2, 2014 23:04:12');
var_dump($datetime3);
