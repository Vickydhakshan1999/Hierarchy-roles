from django.db import models

CUSTOM_FIELD_TYPE = (
    ("text_box", "Text Box"),
    ("website_url", "Website URL"),
    ("text_area", "TextArea"),
    ("number", "Number"),
    ("email", "Email"),
    ("phone_number", "Phone Number"),
    ("dropdown", "Dropdown"),
    ("radio", "Radio"),
    ("date", "Date"),
    ("time", "Time"),
    ("file", "File Upload"),
    ("multiselect_checkbox", "MultiSelect Checkbox"),
    ("hidden", "Hidden"),
    ("heading", "Heading"),
    ("paragraph", "Paragraph"),
)

CUSTOM_FIELD_SIZE = (
    ("col-md-12", "Large"),
    ("col-md-6", "Medium"),
    ("col-md-4", "Small"),
)

CUSTOM_FIELD_STATUS = (
    ("deleted", "Deleted"),
    ("active", "Active"),
    ("in_active", "InActive"),
)


class CustomFieldBase(models.Model):
    label = models.TextField(max_length=200)
    slug = models.CharField(max_length=200, blank=True)
    field_type = models.CharField(max_length=20, choices=CUSTOM_FIELD_TYPE)
    field_size = models.CharField(
        max_length=20, choices=CUSTOM_FIELD_SIZE, default=CUSTOM_FIELD_SIZE[0][0]
    )
    placeholder = models.CharField(max_length=200, blank=True)
    field_order = models.PositiveIntegerField()
    custom_class_name = models.CharField(max_length=200, blank=True)
    validation_rule = models.JSONField(default=dict)
    is_unique = models.BooleanField(default=False)
    content = models.TextField(blank=True)
    content_size = models.CharField(max_length=200, blank=True)
    content_alignment = models.CharField(max_length=200, blank=True)
    show_on_table = models.BooleanField(default=True)
    status = models.CharField(
        max_length=20, choices=CUSTOM_FIELD_STATUS, default=CUSTOM_FIELD_STATUS[1][0]
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        abstract = True


class CustomFieldValueBase(models.Model):
    text_field = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        abstract = True