<?php
date_default_timezone_set('Asia/Taipei');

// Create DateTime instance
$datetime = new DateTime('2015-05-07 20:00:00');

// Create two weeks interval
$interval = new DateInterval('P2W');

// Modify DateTime instance
$datetime->add($interval);
echo $datetime->format('Y-m-d H:i:s');
