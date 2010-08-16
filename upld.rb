require 'fileutils'
require 'rubygems'
require 'sinatra'
require 'dm-core'
require 'dm-migrations'
require 'dm-validations'
require 'dm-timestamps'
require 'base64'
require 'bcrypt'
require 'json'
require 'rack-flash'
require 'maruku'
require 'pony'

enable :sessions
use Rack::Flash

$RESERVED_URLS = ['admin', 'api', 'login', 'password']

helpers do

  include Rack::Utils
  alias_method :h, :escape_html

  def logged_in?
    if request.cookies['userid']
      true
    else
      false
    end
  end

  def logged_in_api?
    @auth ||=  Rack::Auth::Basic::Request.new(request.env)
    if @auth.provided? && @auth.basic? && @auth.credentials
      @user = User.first(:username => Base64.decode64(@auth.credentials[0]))
      if @user && BCrypt::Password.new(@user.password) ==
      Base64.decode64(@auth.credentials[1])
        true
      end
    end
  end

  def authorize!
    redirect '/' unless logged_in?
  end

  def authorize_api!
    unless logged_in_api?
      response['WWW-Authenticate'] = %(Basic realm="UPLD")
      throw(:halt, [401, 'Not Authorized'])
    end
  end

  def get_userid
    request.cookies['userid']
  end

  def set_userid(id)
    response.set_cookie('userid', id)
  end

  def random_string(len)
    chars = ('a'..'z').to_a + ('A'..'Z').to_a + ('0'..'9').to_a
    r = ''
    len.times { r << chars[rand(62)] }
    r
  end

  def make_permalink
    permalink = ''
    begin
      permalink = random_string(rand(3)+3)
    end while Upload.first(:permalink => permalink) || $RESERVED_URLS.include?(
      permalink)
    permalink
  end

  def markdownify(string)
    Maruku.new(h(string.gsub(/\{:(\\\}|[^\}])*\}/, '')).gsub('@',
      '&#64;')).to_html
  end

end

# ==============
# Setup Database
# ==============

DataMapper.setup(:default, ENV['DATABASE_URL'] || "sqlite://#{Dir.pwd}/my.db")

class User

  include DataMapper::Resource

  property :id, Serial
  property :username, String, :required => true
  property :password, String, :required => true
  property :email, String, :required => true
  property :privileges, Integer, :required => true # 0 = user; 1 = admin
  property :file_limit, Integer, :required => true # File storage limit in MBs
  property :file_used, Integer # The amount of space that was used
  property :created_at, DateTime

  validates_uniqueness_of :username
  validates_uniqueness_of :email

  has n, :uploads

end

class Upload

  include DataMapper::Resource

  property :id, Serial
  property :permalink, String, :required => true # URL used to access it
  property :type, String, :required => true
  property :data, Text, :required => true # Can be a URL, filename or text
  property :size, Integer # The file's size in bytes
  property :views, Integer
  property :created_at, DateTime

  belongs_to :user

end

DataMapper.finalize
DataMapper.auto_upgrade!

# Create an initial user
unless user = User.get(1)
  user = User.new(
    :username => 'admin',
    :password => BCrypt::Password.create('password').to_s,
    :email => 'austin@ausgat.com',
    :privileges => 1,
    :file_limit => 5000)
  user.save!
end

# ========
# User Frontend
# ========

get '/' do
  if logged_in?
    erb :home
  else
    erb :login
  end
end

post '/login/?' do
  unless get_userid
    @user = User.first(:username => params[:username])
    if @user
      if BCrypt::Password.new(@user.password) == params[:password]
        set_userid(@user.id)
        redirect '/'
      else
        flash[:notice] = 'Incorrect password.'
        redirect '/'
      end
    else
      flash[:notice] = 'Incorrect username.'
      redirect '/'
    end
  end
end

get '/logout/?' do
  if get_userid
    response.delete_cookie('userid')
    redirect '/'
  end
end

post '/password/?' do
  authorize!
  @user = User.get(get_userid)
  if @user
    if BCrypt::Password.new(@user.password) == params[:current]
      unless params[:new].strip.empty? || params[:new] == 'New Password'
        @user.password = BCrypt::Password.create(params[:new]).to_s
        if @user.save!
          flash[:notice] = 'Password changed.'
          redirect '/'
        else
          flash[:notice] = "Something's wrong!"
          redirect '/'
        end
      else
        flash[:notice] = 'Invalid new password.'
        redirect '/'
      end
    else
      flash[:notice] = 'Incorrect password.'
      redirect '/'
    end
  else
    flash[:notice] = "Something's wrong!"
    redirect '/'
  end
end

get '/admin/?' do
  authorize!
  @user = User.first(:id => get_userid)
  if @user
    if @user.privileges == 1
      @uploads = Upload.all
      @users = User.all
      @storage_used = 0
      @users.each do |user|
        user.file_used = 0 if user.file_used.nil?
        @storage_used += user.file_used
      end
      @storage_used /= 1048576
      erb :admin
    else
      redirect '/'
    end
  else
    redirect '/'
  end
end

post '/admin/invite/?' do
  authorize!
  @user = User.first(:id => get_userid)
  if @user
    if @user.privileges == 1
      unless params[:username].empty? || params[:email].empty? ||
      params[:space].empty?
        @new_user = User.new(
          :username => params[:username],
          :password => BCrypt::Password.create('password').to_s,
          :email => params[:email],
          :privileges => 0,
          :file_limit => params[:space].to_i)
        if @new_user.save!
          Pony.mail :to => @new_user.email,
                     :from => @user.email,
                     :subject => 'UPLD Invite',
                     :body => %{\
You have been invited to UPLD, a simple, private file sharing service. Go \
to http://upld.ausgat.com/ and sign in with the username \
"#{@new_user.username}" and the password "password". Please change your \
password as soon as you can.
}
          flash[:notice] = 'User invited.'
          redirect '/admin'
        else
          flash[:notice] = 'Error inviting user.'
          redirect '/admin'
        end
      else
        flash[:notice] = 'Missing something.'
        redirect '/admin'
      end
    else
      redirect '/'
    end
  else
    redirect '/'
  end
end

# ===========
# API Backend
# ===========

get '/api/index/?' do
  authorize_api!
  if @user
    uploads = @user.uploads.all.collect do |upload|
      upload.attributes
    end
    JSON.generate(uploads)
  else
    throw(:halt, [401, 'Not Authorized'])
  end
end

post '/api/shorten/?' do
  authorize_api!
  if @user
    unless params[:url].empty?
      @upload = @user.uploads.new
      @upload.permalink = make_permalink
      @upload.type = 'link'
      @upload.data = params[:url]
      if @upload.save
        status 200
        JSON.generate(@upload.attributes)
      else
        throw(:halt, [500, 'Internal Server Error'])
      end
    else
      throw(:halt, [400, 'Bad Request'])
    end
  else
    throw(:halt, [401, 'Not Authorized'])
  end
end

post '/api/upload/?' do
  authorize_api!
  if @user
    if params[:file]
      @upload = @user.uploads.new
      @upload.permalink = make_permalink
      @upload.type = 'file'
      allowed_filetypes = ['application/octet-stream', 'image/png',
        'image/jpeg', 'image/jpg', 'image/gif', 'image/tiff', 'video/x-msvideo',
        'video/quicktime', 'video/mp4', 'application/x-tar',
        'application/x-gzip', 'application/x-bzip2', 'application/zip',
        'application/ogg', 'video/ogg', 'audio/ogg', 'audio/mpeg', 'audio/flac']
      if allowed_filetypes.include? params[:file][:type]
        @user.file_used = 0 if @user.file_used.nil?
        @file_size = File::size(params[:file][:tempfile].path)
        if File::size(params[:file][:tempfile].path) < 28992320 &&
        (@user.file_used + File::size(params[:file][:tempfile].path))/1048576 <=
        @user.file_limit
          @filename = "#{@upload.permalink}.#{params[:file][:filename]}"
          FileUtils::copy(params[:file][:tempfile].path, "uploads/#{@filename}")
          @upload.size = @file_size
          @user.file_used = @user.file_used + @upload.size
          @user.save!
        else
          throw(:halt, [413, 'Request Entity Too Large'])
        end
      else
        throw(:halt, [415, 'Unsupported Media Type'])
      end
      @upload.data = @filename
      if @upload.save!
        status 200
        JSON.generate(@upload.attributes)
      else
        throw(:halt, [500, 'Internal Server Error'])
      end
    else
      throw(:halt, [400, 'Bad Request'])
    end
  else
    throw(:halt, [401, 'Not Authorized'])
  end
end

post '/api/paste/?' do
  authorize_api!
  if @user
    unless params[:text].empty?
      @upload = @user.uploads.new
      @upload.permalink = make_permalink
      @upload.type = 'text'
      @upload.data = params[:text]
      if @upload.save
        status 200
        JSON.generate(@upload.attributes)
      else
        throw(:halt, [500, 'Internal Server Error'])
      end
    else
      throw(:halt, [400, 'Bad Request'])
    end
  else
    throw(:halt, [401, 'Not Authorized'])
  end
end

delete '/api/delete/:permalink/?' do
  authorize_api!
  if @user
    unless params[:permalink].empty?
      @upload = @user.uploads.first(:permalink => params[:permalink])
      if @upload
        @file_used = @user.file_used - @upload.size
        @user.file_used = @file_used
        @user.save!
        if @upload.type == 'file'
          File::delete("uploads/#{@upload.data}")
        end
        if @upload.destroy!
          status 200
        else
          throw(:halt, [500, 'Internal Server Error'])
        end
      else
        throw(:halt, [404, 'Not Found'])
      end
    else
      throw(:halt, [400, 'Bad Request'])
    end
  else
    throw(:halt, [401, 'Not Authorized'])
  end
end

# =======================
# Main URL Handling Route
# =======================

get '/*/?' do
  @upload = Upload.first(:permalink => params[:splat])
  if @upload
    views = @upload.views.to_i
    views += 1
    @upload.views = views
    @upload.save

    if @upload.type == 'link'
      redirect @upload.data
    elsif @upload.type == 'file'
      send_file "uploads/#{@upload.data}"
    elsif @upload.type == 'text'
      erb :text, :layout => false
    else
      status 404
      erb :notfound, :layout => false
    end
  else
    status 404
    erb :notfound, :layout => false
  end
end
