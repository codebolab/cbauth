from setuptools import setup, find_packages


packages = find_packages()
install_requires = [
    'rest_framework',
    'rest_framework_simplejwt',
    'allauth',
]


setup(name='cbauth',
      version='1.0',
      description='Django simplified version of authorization with template views and RESTFul API',
      long_description='',
      classifiers=[
          "Programming Language :: Python",
      ],
      author='code.bo',
      author_email='info@code.bo',
      url='https://github.com/codebolab/auth',
      packages=packages,
      include_package_data=True,
      package_data={
          '': [
              'cbauth/templates/*.html'
          ],
      },
      install_requires=install_requires,
      zip_safe=False)
