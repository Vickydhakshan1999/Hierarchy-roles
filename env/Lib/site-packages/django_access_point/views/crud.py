from django.core.exceptions import ImproperlyConfigured
from django.db.models import Prefetch
from django.shortcuts import get_object_or_404
from django.core.paginator import Paginator, EmptyPage, PageNotAnInteger
from rest_framework import viewsets, status
from rest_framework.response import Response

from django_access_point.models.custom_field import CUSTOM_FIELD_TYPE, CUSTOM_FIELD_STATUS


class CrudViewSet(viewsets.GenericViewSet):
    """
    Base view class for CRUD operations.
    Child classes must define `queryset` and `serializer_class`.
    Optionally, `custom_field_model` and `custom_field_value_model` can also be set.
    """

    queryset = None  # Should be defined in the child class
    serializer_class = None  # Should be defined in the child class
    custom_field_model = None  # Optional, should be defined in the child class if needed
    custom_field_value_model = None  # Optional, should be defined in the child class if needed
    custom_field_values_related_name = "custom_field_values"

    def __validate_custom_fields_attributes(self):
        """
        Validates that if `custom_field_model` is defined, `custom_field_value_model` must also be defined.
        Validates that if `custom_field_value_model` is defined, `custom_field_model` must also be defined.
        """
        if self.custom_field_model and not self.custom_field_value_model:
            raise ImproperlyConfigured(
                "Django Access Point: 'custom_field_value_model' must be defined if 'custom_field_model' is set."
            )
        elif self.custom_field_value_model and not self.custom_field_model:
            raise ImproperlyConfigured(
                "Django Access Point: 'custom_field_model' must be defined if 'custom_field_value_model' is set."
            )

    def get_serializer_context(self):
        context = super().get_serializer_context()

        # Add custom field model to context if they are defined
        if self.custom_field_model:
            context["custom_field_model"] = self.custom_field_model
        # Add custom field value model to context if they are defined
        if self.custom_field_value_model:
            context["custom_field_value_model"] = self.custom_field_value_model

        # Add custom_field_queryset to context
        if self.custom_field_model and self.custom_field_value_model:
            context["custom_field_queryset"] = self.get_custom_field_queryset()

        return context

    def get_custom_field_queryset(self):
        """
        Get Custom Field QuerySet
        This method can be overridden by child class to define custom field queryset
        """
        active_custom_fields = self.custom_field_model.objects.filter(
            status=CUSTOM_FIELD_STATUS[1][0]
        ).order_by("field_order")

        return active_custom_fields

    def get_queryset(self):
        # Get the base queryset defined in the child class
        queryset = super().get_queryset()

        # Check if custom_field_model& custom_field_value_model are defined in the child class
        if (
            hasattr(self, "custom_field_model") and self.custom_field_model
            and hasattr(self, "custom_field_value_model") and self.custom_field_value_model
        ):
            # Prefetch the custom field values for the user where the custom field is active
            active_custom_fields = self.get_custom_field_queryset()

            # Prefetch related custom field values
            queryset = queryset.prefetch_related(
                Prefetch(
                    self.custom_field_values_related_name,  # The related name on CRUD model for custom field values
                    queryset=self.custom_field_value_model.objects.filter(
                        custom_field__in=active_custom_fields
                    ).only('id', 'custom_field', 'text_field')
                    # to_attr='custom_field_values'  # Store prefetch result in a custom attribute
                )
            )

        return queryset

    def get_list_fields(self):
        """
        This method should be overridden by child class to define the list fields,
        or the child class should define a `list_fields` attribute.
        """
        if hasattr(self, "list_fields") and isinstance(self.list_fields, dict) and self.list_fields:
            return self.list_fields
        else:
            raise ImproperlyConfigured(
                "Django Access Point: Either 'list_fields' or 'get_list_fields' must be defined and return a dict."
            )

    def format_custom_field_submitted_values(self, custom_field_submitted_values):
        """
        Format Custom Field Submitted Values
        This method can be overridden by child class to format custom field submitted values
        """
        formatted_values = {}
        for submitted_value in custom_field_submitted_values:
            if submitted_value.custom_field.field_type == CUSTOM_FIELD_TYPE[0][0]:
                formatted_values[submitted_value.custom_field.id] = submitted_value.text_field
            elif submitted_value.custom_field.field_type ==  CUSTOM_FIELD_TYPE[1][0]:
                formatted_values[submitted_value.custom_field.id] = submitted_value.text_field.strftime("%Y-%m-%d")
            else:
                formatted_values[submitted_value.custom_field.id] = submitted_value.text_field

        return formatted_values

    def list(self, request, *args, **kwargss):
        """
        List all objects in the queryset with pagination and ordering.
        """
        list_fields_to_use = self.get_list_fields()

        # Ensure that the list_fields_to_use is a dictionary
        if not isinstance(list_fields_to_use, dict) or not list_fields_to_use:
            raise ValueError(
                "Django Access Point: 'list_fields' or 'get_list_fields' must return a dictionary."
            )

        queryset = self.get_queryset()

        # Pagination parameters from the request
        page = request.query_params.get("page", 1)  # Default to page 1
        page_size = request.query_params.get("page_size", 10)  # Default to 10 items per page

        try:
            page = int(page)
            page_size = int(page_size)
        except ValueError:
            return Response(
                {
                    "status": "error",
                    "msg": "Invalid page or page_size parameter",
                    "data": {},
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Handle ordering (order_by and direction)
        order_by = request.query_params.get("order_by", "created_at")  # Default to 'created_at'
        direction = request.query_params.get("direction", "desc")  # Default to 'desc'

        # Validate order_by field
        if order_by not in ["created_at", "updated_at"]:
            return Response(
                {
                    "status": "error",
                    "msg": "Invalid order_by field. Only 'created_at' or 'updated_at' are allowed.",
                    "data": {},
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Validate direction field
        if direction not in ["asc", "desc"]:
            return Response(
                {
                    "status": "error",
                    "msg": "Invalid direction. Only 'asc' or 'desc' are allowed.",
                    "data": {},
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Apply ordering
        if direction == "desc":
            order_by = f"-{order_by}"  # Prefix with '-' for descending order
        queryset = queryset.order_by(order_by)

        # Set up paginator
        paginator = Paginator(queryset, page_size)

        # Handle empty or invalid page
        try:
            page_obj = paginator.get_page(page)
        except (EmptyPage, PageNotAnInteger):
            return Response(
                {
                    "status": "error",
                    "msg": "Invalid Page",
                    "data": {},
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Handle the case when page is out of range
        if page_obj.number > paginator.num_pages:
            return Response(
                {
                    "status": "error",
                    "msg": "Invalid Page",
                    "data": {
                        "per_page": 0,
                        "page": 0,
                        "total": 0,
                        "total_pages": 0,
                        "data": [],
                    },
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Column Headers
        column_headers = list(list_fields_to_use.values())

        # Column Headers - Custom Fields Start
        active_custom_fields = dict()

        if (
            hasattr(self, "custom_field_model") and self.custom_field_model
            and hasattr(self, "custom_field_value_model") and self.custom_field_value_model
        ):
            # If custom_field_model& custom_field_value_model are defined in the child class
            for custom_field in self.get_custom_field_queryset():
                active_custom_fields[custom_field.id] = {
                    "field_type": custom_field.field_type,
                    "field_label": custom_field.label,
                }

                column_headers.append(custom_field.label)
        # Column Headers - Custom Fields End

        # Prepare the data rows
        data = []
        for obj in page_obj.object_list:
            formatted_custom_field_submitted_values = dict()

            if hasattr(obj, self.custom_field_values_related_name):
                # If has "Custom Field" mapped, for every 'data row' get "Custom Field Values"
                custom_field_submitted_values = getattr(obj, self.custom_field_values_related_name).all()
                formatted_custom_field_submitted_values = self.format_custom_field_submitted_values(custom_field_submitted_values)

            row = []
            for field in list_fields_to_use:
                row.append(getattr(obj, field, ""))  # Extract values based on defined fields

            if active_custom_fields:
                # Loop Active Custom Fields & get Submitted Values
                for custom_field in active_custom_fields:
                    row.append(formatted_custom_field_submitted_values.get(custom_field, ""))

            data.append(row)

        # Prepare the response data with pagination info and the rows
        response_data = {
            "per_page": page_obj.paginator.per_page,
            "page": page_obj.number,
            "total": page_obj.paginator.count,
            "total_pages": page_obj.paginator.num_pages,
            "columns": column_headers,
            "data": data,
        }

        return Response(
            {"status": "success", "data": response_data}, status=status.HTTP_200_OK
        )

    def create(self, request, *args, **kwargss):
        """
        Create a new object.
        """
        self.__validate_custom_fields_attributes()

        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid():
            serializer.save()

            return Response(
                {"status": "success", "data": serializer.data},
                status=status.HTTP_201_CREATED,
            )

        return Response(
            {"status": "validation_error", "data": serializer.errors},
            status=status.HTTP_400_BAD_REQUEST,
        )

    def retrieve(self, request, pk=None, *args, **kwargs):
        """
        Retrieve a single object by primary key.
        """
        queryset = self.get_queryset()
        instance = get_object_or_404(queryset, pk=pk)
        serializer = self.get_serializer(instance)

        return Response(serializer.data)

    def update(self, request, pk=None, *args, **kwargs):
        """
        Update an existing object by primary key.
        """
        queryset = self.get_queryset()
        instance = get_object_or_404(queryset, pk=pk)
        serializer = self.get_serializer(instance, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def destroy(self, request, pk=None, *args, **kwargs):
        """
        Delete an object by primary key.
        """
        queryset = self.get_queryset()
        instance = get_object_or_404(queryset, pk=pk)
        instance.delete()

        return Response(status=status.HTTP_204_NO_CONTENT)