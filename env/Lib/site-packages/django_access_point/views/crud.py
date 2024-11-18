from django.shortcuts import get_object_or_404
from rest_framework import viewsets, status
from rest_framework.response import Response


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

    def get_serializer_context(self):
        context = super().get_serializer_context()

        # Add custom field models to context if they are defined
        if self.custom_field_model:
            context["custom_field_model"] = self.custom_field_model
        if self.custom_field_value_model:
            context["custom_field_value_model"] = self.custom_field_value_model

        return context

    def list(self, request, *args, **kwargs):
        """
        List all objects in the queryset.
        """
        queryset = self.get_queryset()
        serializer = self.get_serializer(queryset, many=True)

        return Response(serializer.data)

    def create(self, request, *args, **kwargs):
        """
        Create a new object.
        """
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

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
