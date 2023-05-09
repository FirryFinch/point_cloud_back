import laspy


def get_las_data(url):
    las = laspy.read(url)
    return las.xyz
