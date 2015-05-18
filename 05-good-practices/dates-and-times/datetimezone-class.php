<?php
date_default_timezone_set('Asia/Taipei');

$timezone = new DateTimeZone('Asia/Taipei');
$datetime = new \DateTime('2014-08-20', $timezone);
$datetime->setTimezone(new DateTimeZone('Asia/Hong_Kong'));
