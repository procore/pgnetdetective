#!/bin/bash

dir=$(cd -P -- "$(dirname -- "$0")" && pwd -P)

psql -f $dir/setup.sql -d postgres
psql -f $dir/setup_table.sql -d apple_picker_extreme
psql -f $dir/seed_db.sql -d apple_picker_extreme
