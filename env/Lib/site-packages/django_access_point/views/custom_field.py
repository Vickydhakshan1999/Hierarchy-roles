from django.shortcuts import get_object_or_404
from rest_framework import viewsets, status
from rest_framework.response import Response
from rest_framework.decorators import action


class CustomFieldViewSet(viewsets.GenericViewSet):
    """
    Base view class for Custom Field CRUD operations.
    Child classes must define `queryset` and `serializer_class`.
    """

    queryset = None  # Should be defined in the child class
    serializer_class = None  # Should be defined in the child class

    def list(self, request, *args, **kwargs):
        """
        List all objects in the queryset.
        """
        queryset = self.get_queryset()
        serializer = self.get_serializer(queryset, many=True)

        response_data = {
                "data": serializer.data,
        }

        return Response({
            "status": "success",
            "data": response_data
        }, status=status.HTTP_200_OK)

    def create(self, request, *args, **kwargs):
        """
        Create a new object.
        """
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid():
            serializer.save()

            return Response({
                "status": "success",
                "data": serializer.data
            }, status=status.HTTP_201_CREATED)

        return Response({
            "status": "validation_error",
            "data": serializer.errors
        }, status=status.HTTP_400_BAD_REQUEST)

    def retrieve(self, request, pk=None, *args, **kwargs):
        """
        Retrieve a single object by primary key.
        """
        queryset = self.get_queryset()
        custom_field = get_object_or_404(queryset, pk=pk)
        serializer = self.get_serializer(custom_field)

        return Response(serializer.data)

    def update(self, request, pk=None, *args, **kwargs):
        """
        Update an existing object by primary key.
        """
        queryset = self.get_queryset()
        custom_field = get_object_or_404(queryset, pk=pk)
        serializer = self.get_serializer(custom_field, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def destroy(self, request, pk=None, *args, **kwargs):
        """
        Delete an object by primary key.
        """
        queryset = self.get_queryset()
        custom_field = get_object_or_404(queryset, pk=pk)
        custom_field.delete()

        return Response(status=status.HTTP_204_NO_CONTENT)

    @action(detail=False, methods=["post"])
    def reorder(self, request):
        # Implement reorder logic here
        return Response({"status": "reordered"}, status=status.HTTP_200_OK)
