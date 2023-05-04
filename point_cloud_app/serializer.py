from rest_framework import serializers
from .models import Object


class ObjectSerializer(serializers.ModelSerializer):
    created_by_id = serializers.HiddenField(default=serializers.CurrentUserDefault())
    created_by = serializers.CharField(source='created_by.username', read_only=True)

    class Meta:
        model = Object
        fields = '__all__'