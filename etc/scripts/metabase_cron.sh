export PGDATABASE="scancodeio"
export PGPASSWORD=$DB_PASSWORD
export PGHOST=$DB_HOSTNAME
export PGUSER=$DB_USERNAME

psql -c "REFRESH MATERIALIZED VIEW sca_actionable_items;" 
