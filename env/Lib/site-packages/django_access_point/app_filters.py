import django_filters

from .models import User


class UserSearchFilter(django_filters.FilterSet):
    search = django_filters.CharFilter(method="filter_by_search")

    class Meta:
        model = User
        fields = []

    def filter_by_search(self, queryset, name, value):
        return queryset.filter(
            models.Q(name__icontains=value)
            | models.Q(user_custom_field_values__text_field__icontains=value)
        ).distinct()
