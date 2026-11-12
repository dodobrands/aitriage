from django.db import migrations

TABLE = "shop_order"


def backfill(apps, schema_editor):
    schema_editor.execute("UPDATE " + TABLE + " SET status = 'new' WHERE status IS NULL")


class Migration(migrations.Migration):
    dependencies = [("shop", "0001_initial")]
    operations = [migrations.RunPython(backfill)]
