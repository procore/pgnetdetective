#!/bin/bash
psql -f setup.sql -d postgres
psql -f setup_table.sql -d apple_picker_extreme
psql -f seed_db.sql -d apple_picker_extreme
