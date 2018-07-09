Rails.application.routes.draw do
  # For details on the DSL available within this file, see http://guides.rubyonrails.org/routing.html
  root 'static_pages#home'
  get '/twitter-auth', to: 'static_pages#login'
  get '/sign-in-with-twitter', to: 'static_pages#signin'
  get '/new_post', to: 'static_pages#new'
  post '/create_post', to: 'static_pages#create'
  post '/logout', to: 'static_pages#logout'
end
