-- v4: matcher-form keys per affected row. `product_squash` is squash(product_raw)
-- (vendor kept, lists unsplit), which cannot be compared directly with the
-- matcher's vendor/edition-stripped, list-split forms. `product_keys` holds
-- those forms (space-delimited, with leading and trailing space) so the
-- rematch prefilter can use `LIKE '% key %'`. Existing rows are filled at startup.
ALTER TABLE cve_affected ADD COLUMN product_keys TEXT;
