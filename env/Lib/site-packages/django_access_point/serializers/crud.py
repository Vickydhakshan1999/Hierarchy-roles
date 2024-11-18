from django.core.exceptions import ImproperlyConfigured
from rest_framework import serializers
from rest_framework.exceptions import ValidationError

from django_access_point.models.custom_field import CUSTOM_FIELD_STATUS


class CrudSerializer(serializers.ModelSerializer):
    """
    Base serializer class for CRUD operations.
    Child classes must define `model` and `fields`.
    """

    class Meta:
        model = None  # This should be defined in the child class
        fields = None  # This should be defined in the child class
        custom_field_model = None  # This should be defined in the child class
        custom_field_value_model = None  # This should be defined in the child class

    def __init__(self, *args, **kwargs):
        # Ensure that the 'model' and 'fields' are set in the child class Meta
        if not hasattr(self.Meta, "model"):
            raise ImproperlyConfigured(
                "Django Access Point: The 'model' attribute must be defined in the child class Meta."
            )
        if not hasattr(self.Meta, "fields"):
            raise ImproperlyConfigured(
                "Django Access Point: The 'fields' attribute must be defined in the child class Meta."
            )

        super().__init__(*args, **kwargs)

    def validate(self, data):
        tenant = data.get("tenant", None)

        # Access the context here, after the serializer is initialized
        self.custom_field_model = self.context.get("custom_field_model", None)
        self.custom_field_value_model = self.context.get("custom_field_value_model", None)

        if self.custom_field_model:
            custom_fields_data = {}
            custom_field_errors = {}

            for key, value in self.initial_data.items():
                if key.startswith("custom_field_"):
                    # Extract the custom field ID from the key (assuming format is custom_field_<id>)
                    custom_field_id = key.split("_")[2]  # Example: custom_field_1, custom_field_2

                    try:
                        # Check if the custom field exists
                        custom_field = self.custom_field_model.objects.filter(
                            id=custom_field_id,
                            tenant=tenant,
                            status=CUSTOM_FIELD_STATUS[1][0],
                        ).get()
                    except self.custom_field_model.DoesNotExist:
                        # Store the error message if custom field does not exist
                        custom_field_errors["custom_field_" + custom_field_id] \
                            = f"Custom field with ID {custom_field_id} does not exist."
                    else:
                        # If the field exists, add the value to custom_fields_data
                        custom_fields_data[custom_field_id] = value

            # If there are any custom field validation errors, raise validation errors
            if custom_field_errors:
                raise ValidationError(custom_field_errors)

            # Add custom fields data to the validated data if there are no errors
            data["custom_fields"] = custom_fields_data

        return data

    def create(self, validated_data):
        # Extract custom fields data from validated data
        custom_fields_data = validated_data.pop("custom_fields", {})

        # Create the user or relevant model instance
        instance = self.Meta.model.objects.create(**validated_data)

        # Save custom fields (if applicable)
        for field_id, value in custom_fields_data.items():
            try:
                custom_field = self.custom_field_model.objects.get(id=field_id)
                # Logic to save or associate the custom field with the instance (e.g., create a relation)
                # This is just an example:
                # instance.custom_fields.create(custom_field=custom_field, value=value)
            except self.custom_field_model.DoesNotExist:
                raise ValidationError(
                    f"Custom field with ID {field_id} does not exist."
                )

        return instance
