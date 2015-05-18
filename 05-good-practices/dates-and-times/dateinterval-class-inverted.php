<?php
date_default_timezone_set('Asia/Taipei');

$dateStart = new \DateTime();
$dateInterval = \DateInterval::createFromDateString('-1 day');
$datePeriod = new \DatePeriod($dateStart, $dateInterval, 3);
foreach ($datePeriod as $date) {
    echo $date->format('Y-m-d'), PHP_EOL;
}

function exception_handler_1(Exception $e)
    {
        echo '[' . __FUNCTION__ . '] ' . $e->getMessage();
    }

    function exception_handler_2(Exception $e)
    {
        echo '[' . __FUNCTION__ . '] ' . $e->getMessage();
    }

    set_exception_handler('exception_handler_1');
    set_exception_handler('exception_handler_2');

    restore_exception_handler();

    throw new Exception('This triggers the first exception handler...');
