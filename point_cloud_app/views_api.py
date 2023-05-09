import json

from django.contrib.auth import authenticate, login, logout
from django.middleware.csrf import get_token
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_protect
from rest_framework import permissions
from rest_framework.response import Response
from rest_framework.views import APIView

from point_cloud_app.las_to_json_coordinates import get_las_data
from point_cloud_app.models import Class, Subclass, Object
from point_cloud_app.serializer import ClassSerializer, SubclassSerializer, ObjectSerializer


@method_decorator(csrf_protect, name='dispatch')
class GetCSRF(APIView):
    permission_classes = (permissions.AllowAny,)

    def get(self, request):
        response = Response({'detail': 'CSRF cookie successfully set'})
        response['X-CSRFToken'] = get_token(request)
        return response


@method_decorator(csrf_protect, name='dispatch')
class SessionView(APIView):
    permission_classes = (permissions.AllowAny,)

    def get(self, request):
        if not request.user.is_authenticated:
            return Response({'isAuthenticated': False})

        return Response({'isAuthenticated': True})


@method_decorator(csrf_protect, name='dispatch')
class LoginView(APIView):
    permission_classes = (permissions.AllowAny,)

    def post(self, request):
        data = json.loads(request.body)
        username = data.get('username')
        password = data.get('password')

        if username is None or password is None:
            return Response({'detail': 'Please provide username and password'}, status=400)

        user = authenticate(username=username, password=password)

        first_name = user.first_name
        last_name = user.last_name

        if user is None:
            return Response({'detail': 'Invalid credentials'}, status=400)

        login(request, user)

        if user.is_staff or user.is_superuser:
            group = 'admin'
        else:
            group = 'user'

        return Response({'detail': 'Successfully logged in', 'username': username, 'first_name': first_name,
                         'last_name': last_name, 'group': group})


class LogoutView(APIView):
    permission_classes = (permissions.AllowAny,)

    def get(self, request):
        if not request.user.is_authenticated:
            return Response({'detail': 'You\'re not logged in'}, status=400)
        logout(request)
        return Response({'detail': 'Successfully logged out'})


class WhoAmI(APIView):
    permission_classes = (permissions.AllowAny,)

    def get(self, request):
        if not request.user.is_authenticated:
            return Response({'isAuthenticated': False})

        if request.user.is_staff or request.user.is_superuser:
            group = 'admin'
        else:
            group = 'user'

        return Response({'username': request.user.username, 'first_name': request.user.first_name,
                         'last_name': request.user.last_name,
                         'group': group})


class ClassesView(APIView):
    def get(self, request):
        output = [
            {
                "title": output.title
            } for output in Class.objects.all()
        ]
        return Response(output)

    def post(self, request):
        serializer = ClassSerializer(data=request.data)
        if serializer.is_valid(raise_exception=True):
            serializer.save()
            return Response(serializer.data)


class CustomEncoder(json.JSONEncoder):
    def default(self, o):
        return o.__dict__


class SubclassesView(APIView):
    def get(self, request):
        output = [
            {
                "title": output.title,
                "cl": output.cl.title
            } for output in Subclass.objects.all()
        ]
        return Response(output)

    def post(self, request):
        serializer = SubclassSerializer(data=request.data)
        if serializer.is_valid(raise_exception=True):
            serializer.save()
            return Response(serializer.data)


class ObjectsView(APIView):
    def get(self, request):
        output = [
            {
                "name": output.name,
                "cl": output.subcl.cl.title,
                "subcl": output.subcl.title,
                "length": output.length,
                "width": output.width,
                "height": output.height,
                "time_create": output.time_create,
                "created_by": output.created_by.username,
                "time_update": output.time_update,
                "num": output.num,
                "file_url": output.file.url,
                "file_data": get_las_data(output.file)
            } for output in Object.objects.all()
        ]
        return Response(output)

    def post(self, request):
        serializer = ObjectSerializer(data=request.data)
        if serializer.is_valid(raise_exception=True):
            serializer.save()
            return Response(serializer.data)
